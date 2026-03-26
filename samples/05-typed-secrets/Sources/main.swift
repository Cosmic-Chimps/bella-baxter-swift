// Typed Secrets sample — one secret per Bella type:
//   String → externalApiKey, gleapApiKey, connectionStringsPostgres
//   Int    → port
//   Bool   → enableFeatures
//   Uri    → databaseUrl   ← Foundation URL
//   JSON   → appConfig     ← Codable struct
//   GUID   → appId         ← Foundation UUID
//
// Workflow:
//   bella secrets generate swift -o Sources/AppSecrets.swift
//   bella run -- swift run
import Foundation

let s = AppSecrets()
let cfg = s.appConfig

print("=== Bella Baxter: Typed Secrets (Swift) ===")
print("")
print("String  EXTERNAL_API_KEY           : \(String(s.externalApiKey.prefix(4)))***")
print("String  GLEAP_API_KEY              : \(String(s.gleapApiKey.prefix(4)))***")
print("Int     PORT                       : \(s.port)  ← type: Int")
print("Bool    ENABLE_FEATURES            : \(s.enableFeatures)  ← type: Bool")
print("Uri     DATABASE_URL               : scheme=\(s.databaseUrl.scheme ?? "")  ← type: URL")
print("JSON    APP_CONFIG.setting1        : \(cfg.setting1)  ← String")
print("JSON    APP_CONFIG.setting2        : \(cfg.setting2)  ← Int")
print("GUID    APP_ID                     : \(s.appId)  ← type: UUID")
print("String  ConnectionStrings__Postgres: \(String(s.connectionStringsPostgres.prefix(8)))...")
print("")
print("No raw ProcessInfo.processInfo.environment calls — secrets are typed, validated, and structured.")
