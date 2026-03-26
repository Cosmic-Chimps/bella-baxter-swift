import SwiftUI
import BellaBaxterSwift

// MARK: - How to integrate BellaBaxterSwift in an iOS app

/// The Bella client is typically initialized once at app startup and stored
/// in the SwiftUI environment or as a singleton.
///
/// Add BellaBaxterSwift as a SwiftPM dependency in your Xcode project:
///
///   File → Add Package Dependencies →
///   https://github.com/cosmic-chimps/bella-baxter-swift
///
/// Then retrieve and inject secrets at startup:
///
/// ```swift
/// @main
/// struct MyApp: App {
///     var body: some Scene {
///         WindowGroup {
///             ContentView()
///                 .task { await loadSecrets() }
///         }
///     }
///
///     func loadSecrets() async {
///         guard let url = URL(string: Bundle.main.infoDictionary?["BELLA_URL"] as? String ?? "") else { return }
///         let apiKey = Bundle.main.infoDictionary?["BELLA_API_KEY"] as? String ?? ""
///         let client = try? BellaClient(BellaClientOptions(baseURL: url, apiKey: apiKey))
///         if let secrets = try? await client?.pullSecrets(projectRef: "my-ios-app", environmentSlug: "production") {
///             // Use secrets — e.g. configure backend URL, feature flags, etc.
///             AppConfig.shared.configure(from: secrets)
///         }
///     }
/// }
/// ```

// MARK: - ViewModel example

@MainActor
final class ProjectsViewModel: ObservableObject {
    @Published var projects: [Project] = []
    @Published var isLoading = false
    @Published var errorMessage: String?

    private let client: BellaClient

    init(client: BellaClient) {
        self.client = client
    }

    func load() async {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }
        do {
            let apiProjects = try await client.listProjects()
            projects = apiProjects.compactMap { p in
                guard let id = p.id, let name = p.name, let slug = p.slug else { return nil }
                return Project(id: id, name: name, slug: slug, description: p.description)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

struct Project: Identifiable {
    let id: String
    let name: String
    let slug: String
    let description: String?
}

// MARK: - View example

struct ProjectsListView: View {
    @StateObject private var vm: ProjectsViewModel

    init(client: BellaClient) {
        _vm = StateObject(wrappedValue: ProjectsViewModel(client: client))
    }

    var body: some View {
        List(vm.projects) { project in
            VStack(alignment: .leading, spacing: 4) {
                Text(project.name).font(.headline)
                Text(project.slug).font(.caption).foregroundStyle(.secondary)
                if let desc = project.description {
                    Text(desc).font(.caption2).foregroundStyle(.tertiary)
                }
            }
            .padding(.vertical, 4)
        }
        .navigationTitle("Projects")
        .overlay {
            if vm.isLoading { ProgressView() }
            if let err = vm.errorMessage { Text(err).foregroundStyle(.red) }
        }
        .task { await vm.load() }
    }
}
