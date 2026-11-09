//
//  LicenceManager.swift — HANA
//
//  Activation et vérification de la licence côté app macOS (macOS 12+).
//  - Identifie le Mac (UUID matériel, haché)
//  - Active la clé auprès du workflow n8n
//  - Vérifie la signature Ed25519 de la licence (CryptoKit)
//  - Stocke la licence dans le Trousseau
//  - Fournit l'en-tête à envoyer au backend Flask
//
//  Entitlement requis si l'app est sandboxée : com.apple.security.network.client
//

import Foundation
import CryptoKit
import IOKit
import Security

// MARK: - Configuration

enum LicenceConfig {
    /// URL du webhook n8n (production, HTTPS obligatoire)
    static let activationURL = URL(string: "https://n8n.votre-domaine.com/webhook/hana/activate")!
    static let deactivationURL = URL(string: "https://n8n.votre-domaine.com/webhook/hana/deactivate")!

    /// Clé PUBLIQUE produite par generer-cles.js (32 octets en base64). Jamais la clé privée !
    static let publicKeyBase64 = "REMPLACER_PAR_LA_CLE_PUBLIQUE"

    /// On tente une revalidation silencieuse si la licence a été émise il y a plus de 24 h
    static let intervalleRevalidation: TimeInterval = 24 * 3600

    static let keychainService = "com.votresociete.hana.licence"
}

// MARK: - Modèles

/// Contenu signé par le serveur (dates en secondes Unix)
struct Licence: Codable {
    let key: String
    let machineId: String
    let plan: String
    let expiresAt: TimeInterval?
    let issuedAt: TimeInterval
    let validUntil: TimeInterval
}

/// Ce que renvoie n8n et ce qu'on stocke dans le Trousseau
struct LicenceSignee: Codable {
    let payload: String     // JSON en base64, signé tel quel
    let signature: String   // signature Ed25519 en base64

    /// Format de l'en-tête X-Hana-Licence envoyé à Flask : "<payload>.<signature>"
    var jeton: String { "\(payload).\(signature)" }
}

enum LicenceErreur: LocalizedError {
    case nonActivee
    case formatInvalide
    case signatureInvalide
    case autreMachine
    case expiree
    case aRevalider
    case refusServeur(code: Int, message: String)
    case reseau(Error)

    var errorDescription: String? {
        switch self {
        case .nonActivee:        return "Aucune licence n'est activée sur ce Mac."
        case .formatInvalide:    return "Licence illisible."
        case .signatureInvalide: return "Licence falsifiée ou corrompue."
        case .autreMachine:      return "Cette licence a été activée sur un autre Mac."
        case .expiree:           return "Votre licence a expiré."
        case .aRevalider:        return "Connectez-vous à Internet pour revalider votre licence."
        case .refusServeur(_, let message): return message
        case .reseau(let e):     return "Serveur de licence injoignable : \(e.localizedDescription)"
        }
    }

    /// Le serveur a explicitement refusé (clé inconnue, révoquée, limite atteinte…)
    var estRefusDefinitif: Bool {
        if case .refusServeur(let code, _) = self { return code == 403 || code == 404 }
        return false
    }
}

// MARK: - Gestionnaire

@MainActor
final class LicenceManager: ObservableObject {

    static let shared = LicenceManager()

    @Published private(set) var licence: Licence?
    @Published private(set) var erreur: LicenceErreur?

    var estValide: Bool { licence != nil }

    private init() {}

    // MARK: Démarrage de l'app

    /// À appeler au lancement. Renvoie true si l'app peut être utilisée.
    @discardableResult
    func verifierAuDemarrage() async -> Bool {
        guard let signee = Trousseau.lire() else {
            appliquer(nil, .nonActivee); return false
        }

        let lic: Licence
        do {
            lic = try Self.verifier(signee, horloge: Date())
        } catch let e as LicenceErreur {
            // Licence locale périmée : on tente une revalidation en ligne
            if case .aRevalider = e, let cle = Self.cleSansVerifierDate(signee) {
                return await revalider(cle: cle, licenceLocale: nil)
            }
            Trousseau.supprimer()
            appliquer(nil, e); return false
        } catch {
            appliquer(nil, .formatInvalide); return false
        }

        appliquer(lic, nil)

        // Licence valide : revalidation silencieuse si elle date un peu
        if Date().timeIntervalSince1970 - lic.issuedAt > LicenceConfig.intervalleRevalidation {
            Task { await self.revalider(cle: lic.key, licenceLocale: lic) }
        }
        return true
    }

    // MARK: Activation (écran « Entrer votre clé »)

    func activer(cle: String) async throws {
        do {
            let signee = try await Self.appelerServeur(LicenceConfig.activationURL, cle: cle)
            let lic = try Self.verifier(signee, horloge: Date())
            try Trousseau.enregistrer(signee)
            appliquer(lic, nil)
        } catch let e as LicenceErreur {
            appliquer(nil, e); throw e
        }
    }

    /// Libère ce Mac pour pouvoir activer la licence sur un autre
    func desactiver() async {
        if let cle = licence?.key {
            _ = try? await Self.appelerServeur(LicenceConfig.deactivationURL, cle: cle, attendLicence: false)
        }
        Trousseau.supprimer()
        appliquer(nil, .nonActivee)
    }

    /// En-tête à ajouter à chaque requête vers le backend Flask
    func ajouterEntetes(_ requete: inout URLRequest) {
        if let signee = Trousseau.lire() {
            requete.setValue(signee.jeton, forHTTPHeaderField: "X-Hana-Licence")
            requete.setValue(Self.machineId(), forHTTPHeaderField: "X-Hana-Machine")
        }
    }

    // MARK: Interne

    @discardableResult
    private func revalider(cle: String, licenceLocale: Licence?) async -> Bool {
        do {
            try await activer(cle: cle)
            return true
        } catch let e as LicenceErreur where e.estRefusDefinitif {
            Trousseau.supprimer()           // révoquée, expirée, limite atteinte…
            appliquer(nil, e); return false
        } catch {
            // Hors ligne : on garde la licence locale tant que validUntil n'est pas dépassé
            if let lic = licenceLocale { appliquer(lic, nil); return true }
            appliquer(nil, .aRevalider); return false
        }
    }

    private func appliquer(_ lic: Licence?, _ err: LicenceErreur?) {
        licence = lic
        erreur = err
    }

    // MARK: Vérification cryptographique

    nonisolated static func verifier(_ signee: LicenceSignee, horloge: Date) throws -> Licence {
        guard
            let payloadData = Data(base64Encoded: signee.payload),
            let signature = Data(base64Encoded: signee.signature),
            let cleData = Data(base64Encoded: LicenceConfig.publicKeyBase64),
            let clePublique = try? Curve25519.Signing.PublicKey(rawRepresentation: cleData)
        else { throw LicenceErreur.formatInvalide }

        guard clePublique.isValidSignature(signature, for: payloadData) else {
            throw LicenceErreur.signatureInvalide
        }

        guard let lic = try? JSONDecoder().decode(Licence.self, from: payloadData) else {
            throw LicenceErreur.formatInvalide
        }

        guard lic.machineId == machineId() else { throw LicenceErreur.autreMachine }

        let maintenant = horloge.timeIntervalSince1970
        if let exp = lic.expiresAt, exp < maintenant { throw LicenceErreur.expiree }
        // Horloge reculée de plus d'un jour avant l'émission : suspect
        if maintenant < lic.issuedAt - 86400 { throw LicenceErreur.aRevalider }
        if maintenant > lic.validUntil { throw LicenceErreur.aRevalider }

        return lic
    }

    /// Récupère la clé d'une licence correctement signée, même périmée (pour la revalider)
    nonisolated private static func cleSansVerifierDate(_ signee: LicenceSignee) -> String? {
        guard
            let payloadData = Data(base64Encoded: signee.payload),
            let signature = Data(base64Encoded: signee.signature),
            let cleData = Data(base64Encoded: LicenceConfig.publicKeyBase64),
            let clePublique = try? Curve25519.Signing.PublicKey(rawRepresentation: cleData),
            clePublique.isValidSignature(signature, for: payloadData),
            let lic = try? JSONDecoder().decode(Licence.self, from: payloadData),
            lic.machineId == machineId()
        else { return nil }
        return lic.key
    }

    // MARK: Réseau

    nonisolated private static func appelerServeur(_ url: URL, cle: String,
                                                   attendLicence: Bool = true) async throws -> LicenceSignee {
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        req.httpBody = try JSONEncoder().encode([
            "key": cle.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
            "machineId": machineId(),
            "appVersion": version,
        ])

        let data: Data
        let reponse: URLResponse
        do {
            (data, reponse) = try await URLSession.shared.data(for: req)
        } catch {
            throw LicenceErreur.reseau(error)
        }

        let code = (reponse as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            let message = (try? JSONDecoder().decode([String: String].self, from: data))?["error"]
                ?? "Erreur du serveur de licence (\(code))."
            throw LicenceErreur.refusServeur(code: code, message: message)
        }
        guard attendLicence else { return LicenceSignee(payload: "", signature: "") }
        guard let signee = try? JSONDecoder().decode(LicenceSignee.self, from: data) else {
            throw LicenceErreur.formatInvalide
        }
        return signee
    }

    // MARK: Identifiant du Mac

    /// SHA-256 de l'UUID matériel (IOPlatformUUID), stable même après réinstallation de macOS.
    /// Même calcul que machine_id() dans licence.py.
    nonisolated static func machineId() -> String {
        let service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                  IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(service) }
        let uuid = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString,
                                                   kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String ?? "inconnu"
        let hash = SHA256.hash(data: Data("hana:\(uuid)".utf8))
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Trousseau macOS

enum Trousseau {
    private static let compte = "licence"

    static func enregistrer(_ signee: LicenceSignee) throws {
        let data = try JSONEncoder().encode(signee)
        supprimer()
        let attributs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: LicenceConfig.keychainService,
            kSecAttrAccount as String: compte,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let statut = SecItemAdd(attributs as CFDictionary, nil)
        guard statut == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(statut))
        }
    }

    static func lire() -> LicenceSignee? {
        let requete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: LicenceConfig.keychainService,
            kSecAttrAccount as String: compte,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var resultat: AnyObject?
        guard SecItemCopyMatching(requete as CFDictionary, &resultat) == errSecSuccess,
              let data = resultat as? Data else { return nil }
        return try? JSONDecoder().decode(LicenceSignee.self, from: data)
    }

    static func supprimer() {
        let requete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: LicenceConfig.keychainService,
            kSecAttrAccount as String: compte,
        ]
        SecItemDelete(requete as CFDictionary)
    }
}
