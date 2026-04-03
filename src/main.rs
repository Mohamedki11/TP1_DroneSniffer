//! # Drone Sniffer
//!
//! Outil en ligne de commande pour analyser les trames WiFi
//! d'identification et de localisation de drones.
//!
//! ## Utilisation
//! ```bash
//! cargo run -- --pcap capture.pcapng --packet-count 100
//! cargo run -- --cards
//! cargo run -- --interface wlan0 --filter "wlan type mgt subtype beacon"
//! ```

mod parser; // module d'analyse des trames WiFi
mod output; // module de sauvegarde des résultats

use clap::{Parser, ValueEnum};
use pcap::{Capture, Offline};
use std::collections::HashSet;
use parser::{parse_beacon_frame, parse_drone_frame};
use output::save_results;

/// Format de sortie pour la sauvegarde des résultats
#[derive(Debug, Clone, ValueEnum)]
pub enum Format {
    Json, // format JSON (défaut)
    Csv,  // format CSV
}

/// Arguments de ligne de commande du programme
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Chemin vers le fichier PCAP à analyser
    #[arg(long, conflicts_with = "interface")]
    pcap: Option<String>,

    /// Interface réseau pour la capture en temps réel
    #[arg(long, conflicts_with = "pcap")]
    interface: Option<String>,

    /// Affiche la liste des interfaces disponibles et quitte
    #[arg(long)]
    cards: bool,

    /// Filtre BPF à appliquer (ex: "wlan type mgt subtype beacon")
    #[arg(long)]
    filter: Option<String>,

    /// Nombre maximum de paquets à traiter
    #[arg(long, default_value_t = 10)]
    packet_count: u32,

    /// Format du fichier de sortie
    #[arg(long, default_value = "json")]
    output_format: Format,

    /// Nom du fichier de sortie
    #[arg(long, default_value = "results.json")]
    output_file: String,
}

fn main() {
    let args = Args::parse();

    // --cards : liste les interfaces réseau disponibles et quitte
    if args.cards {
        match pcap::Device::list() {
            Ok(devices) => {
                println!("📡 Interfaces réseau disponibles :");
                for d in devices {
                    println!("   {} — {}",
                        d.name,
                        d.desc.unwrap_or_else(|| "sans description".to_string()));
                }
            }
            Err(e) => eprintln!("❌ Impossible de lister les interfaces : {}", e),
        }
        return;
    }

    // --pcap : lecture depuis un fichier PCAP
    if let Some(ref path) = args.pcap {
        match open_pcap(path) {
            Ok(mut cap) => read_packets(
                &mut cap,
                args.packet_count,
                &args.output_file,
                &args.output_format
            ),
            Err(e) => eprintln!("❌ Impossible d'ouvrir le fichier : {}", e),
        }
        return;
    }

    // --interface : capture en temps réel
    if let Some(ref iface) = args.interface {
        match pcap::Capture::from_device(iface.as_str()) {
            Ok(cap) => {
                match cap.promisc(true).open() {
                    Ok(mut active) => {
                        // Application du filtre BPF si fourni
                        if let Some(ref f) = args.filter {
                            if let Err(e) = active.filter(f, true) {
                                eprintln!("❌ Erreur de filtre : {}", e);
                            }
                        }
                        read_live_packets(
                            &mut active,
                            args.packet_count,
                            &args.output_file,
                            &args.output_format
                        );
                    }
                    Err(e) => eprintln!("❌ Impossible d'ouvrir l'interface : {}", e),
                }
            }
            Err(e) => eprintln!("❌ Interface introuvable : {}", e),
        }
        return;
    }

    eprintln!("❌ Utilisez --pcap <fichier>, --interface <nom> ou --cards");
    std::process::exit(1);
}

/// Ouvre un fichier PCAP et retourne un handle de capture
fn open_pcap(path: &str) -> Result<Capture<Offline>, pcap::Error> {
    Capture::from_file(path)
}

/// Traite un paquet brut et met à jour les structures de données
fn process_packet(
    data: &[u8],
    seen_macs: &mut HashSet<String>,
    seen_ids:  &mut HashSet<String>,
    results:   &mut Vec<parser::DroneFrame>
) {
    // Affiche chaque beacon unique (identifié par son adresse MAC)
    if let Some(beacon) = parse_beacon_frame(data)
        && seen_macs.insert(beacon.mac.clone()) {
            println!("📡 Beacon | MAC : {} | SSID : {}", beacon.mac, beacon.ssid);
    }

    // Affiche et sauvegarde chaque drone unique (identifié par son drone_id)
    if let Some(drone) = parse_drone_frame(data)
        && seen_ids.insert(drone.drone_id.clone()) {
            println!("🛸 Drone détecté !");
            println!("   ID        : {}", drone.drone_id);
            println!("   Latitude  : {:.5}", drone.latitude);
            println!("   Longitude : {:.5}", drone.longitude);
            println!("   Altitude  : {} m", drone.altitude);
            println!("   Vitesse   : {} m/s", drone.speed);
            println!("   Cap       : {} deg\n", drone.heading);
            results.push(drone);
    }
}

/// Lit les paquets depuis un fichier PCAP et extrait les données drone/beacon
fn read_packets(
    cap: &mut Capture<Offline>,
    max: u32,
    output_file: &str,
    format: &Format
) {
    let mut count     = 0;
    let mut seen_ids  = HashSet::new(); // identifiants drone déjà vus
    let mut seen_macs = HashSet::new(); // adresses MAC déjà vues
    let mut results   = Vec::new();     // trames drone collectées

    while let Ok(packet) = cap.next_packet() {
        count += 1;
        if count > max { break; }
        process_packet(packet.data, &mut seen_macs, &mut seen_ids, &mut results);
    }

    println!("✅ {} paquets analysés.", count);
    save_results(&results, output_file, format);
}

/// Lit les paquets depuis une interface réseau en temps réel
fn read_live_packets(
    cap: &mut pcap::Capture<pcap::Active>,
    max: u32,
    output_file: &str,
    format: &Format
) {
    let mut count     = 0;
    let mut seen_ids  = HashSet::new();
    let mut seen_macs = HashSet::new();
    let mut results   = Vec::new();

    println!("📡 Capture en cours... (Ctrl+C pour arrêter)");

    while let Ok(packet) = cap.next_packet() {
        count += 1;
        if count > max { break; }
        process_packet(packet.data, &mut seen_macs, &mut seen_ids, &mut results);
    }

    println!("✅ {} paquets capturés.", count);
    save_results(&results, output_file, format);
}