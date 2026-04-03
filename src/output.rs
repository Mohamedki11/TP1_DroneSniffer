//! # Module output
//! Gère la sauvegarde des résultats d'analyse dans un fichier.
//! Supporte les formats JSON (via serde_json) et CSV (via le crate csv).

use crate::parser::DroneFrame;
use crate::Format;

/// Sauvegarde une liste de trames drone dans le format choisi par l'utilisateur
pub fn save_results(results: &[DroneFrame], path: &str, format: &Format) {
    match format {
        Format::Json => save_json(results, path),
        Format::Csv  => save_csv(results, path),
    }
}

/// Sérialise les trames drone en JSON indenté et écrit dans un fichier
fn save_json(results: &[DroneFrame], path: &str) {
    match serde_json::to_string_pretty(results) {
        Ok(json) => {
            match std::fs::write(path, json) {
                Ok(_)  => println!("💾 Résultats JSON sauvegardés : {}", path),
                Err(e) => eprintln!("❌ Impossible d'écrire le fichier : {}", e),
            }
        }
        Err(e) => eprintln!("❌ Erreur de sérialisation : {}", e),
    }
}

/// Écrit les trames drone dans un fichier CSV, une ligne par drone.
/// Les noms de champs du struct servent automatiquement d'en-têtes CSV.
fn save_csv(results: &[DroneFrame], path: &str) {
    match csv::Writer::from_path(path) {
        Ok(mut writer) => {
            for drone in results {
                if let Err(e) = writer.serialize(drone) {
                    eprintln!("❌ Erreur ligne CSV : {}", e);
                }
            }
            match writer.flush() {
                Ok(_)  => println!("💾 Résultats CSV sauvegardés : {}", path),
                Err(e) => eprintln!("❌ Erreur flush CSV : {}", e),
            }
        }
        Err(e) => eprintln!("❌ Impossible de créer le fichier CSV : {}", e),
    }
}