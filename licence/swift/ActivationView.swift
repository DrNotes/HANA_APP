//
//  ActivationView.swift — HANA
//
//  Écran SwiftUI minimal : bloque l'app tant que la licence n'est pas valide.
//
//  Utilisation dans votre App :
//
//      @main
//      struct HanaApp: App {
//          @StateObject private var licence = LicenceManager.shared
//          var body: some Scene {
//              WindowGroup {
//                  if licence.estValide { ContentView() } else { ActivationView() }
//              }
//          }
//      }
//

import SwiftUI

struct ActivationView: View {
    @ObservedObject private var licence = LicenceManager.shared
    @State private var cle = ""
    @State private var enCours = false
    @State private var verifieAuDemarrage = false

    var body: some View {
        VStack(spacing: 16) {
            Text("Activer HANA").font(.title2.bold())
            Text("Entrez la clé de licence reçue par e-mail.")
                .foregroundStyle(.secondary)

            TextField("HANA-XXXX-XXXX-XXXX", text: $cle)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .frame(width: 280)
                .onSubmit(activer)

            if let erreur = licence.erreur, erreur.errorDescription != LicenceErreur.nonActivee.errorDescription {
                Text(erreur.localizedDescription)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Button(action: activer) {
                if enCours { ProgressView().controlSize(.small) } else { Text("Activer") }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(cle.count < 4 || enCours)
        }
        .padding(32)
        .frame(minWidth: 420, minHeight: 260)
        .task {
            guard !verifieAuDemarrage else { return }
            verifieAuDemarrage = true
            await licence.verifierAuDemarrage()
        }
    }

    private func activer() {
        enCours = true
        Task {
            try? await licence.activer(cle: cle)
            enCours = false
        }
    }
}
