//! # Module parser
//! Contient toutes les fonctions d'analyse des trames WiFi 802.11.
//! Permet d'extraire les informations des trames beacon normales
//! et des trames DroneID conformes à la réglementation française.

use serde::Serialize;

/// OUI identifiant les trames DroneID françaises (6A:5C:35)
/// Défini par l'arrêté publié au Journal Officiel
pub const DRONE_OUI: [u8; 3] = [0x6A, 0x5C, 0x35];

/// Données extraites d'une trame beacon DroneID
#[derive(Debug, Serialize)]
pub struct DroneFrame {
    pub drone_id:  String, // Identifiant complet du drone (fabricant + modèle + série)
    pub mac:       String, // Adresse MAC de l'émetteur
    pub ssid:      String, // Nom du réseau WiFi diffusé
    pub latitude:  f32,    // Latitude GPS en degrés décimaux
    pub longitude: f32,    // Longitude GPS en degrés décimaux
    pub altitude:  i16,    // Altitude AMSL en mètres
    pub speed:     u8,     // Vitesse horizontale en m/s
    pub heading:   u16,    // Cap en degrés (0-359)
}

/// Données extraites d'une trame beacon standard
#[derive(Debug)]
pub struct BeaconFrame {
    pub ssid: String, // Nom du réseau WiFi
    pub mac:  String, // Adresse MAC de l'émetteur
}

/// Tente d'extraire les données DroneID d'un paquet brut.
/// Retourne None si le paquet n'est pas une trame DroneID.
pub fn parse_drone_frame(data: &[u8]) -> Option<DroneFrame> {
    if data.len() < 4 { return None; }

    // La taille de l'en-tête Radiotap est stockée aux octets [2..3] en little-endian
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let rest = data.get(radiotap_len..)?;

    // Premier octet 0x80 = trame beacon
    if rest.first() != Some(&0x80) { return None; }

    // L'adresse MAC source se trouve aux octets 10 à 15 de l'en-tête 802.11
    let mac_bytes = rest.get(10..16)?;
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2],
        mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    // On saute l'en-tête 802.11 (24 octets) + les champs fixes beacon (12 octets)
    let tagged = rest.get(36..)?;
    let ssid = find_ssid(tagged).unwrap_or_else(|| "<caché>".to_string());

    // Recherche et analyse du tag DroneID dans les paramètres TLV
    let mut drone = find_drone_tag(tagged)?;
    drone.mac  = mac;
    drone.ssid = ssid;
    Some(drone)
}

/// Tente d'extraire le SSID et l'adresse MAC d'une trame beacon standard.
/// Retourne None si le paquet n'est pas une trame beacon.
pub fn parse_beacon_frame(data: &[u8]) -> Option<BeaconFrame> {
    if data.len() < 4 { return None; }

    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let rest = data.get(radiotap_len..)?;

    if rest.first() != Some(&0x80) { return None; }

    let mac_bytes = rest.get(10..16)?;
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2],
        mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    let tagged = rest.get(36..)?;
    let ssid = find_ssid(tagged).unwrap_or_else(|| "<caché>".to_string());
    Some(BeaconFrame { ssid, mac })
}

/// Parcourt les paramètres TLV à la recherche du tag Vendor Specific (221)
/// contenant l'OUI DroneID français (6A:5C:35)
fn find_drone_tag(data: &[u8]) -> Option<DroneFrame> {
    let mut i = 0;
    while i + 2 <= data.len() {
        let tag_id  = data[i];
        let tag_len = data[i + 1] as usize;
        let tag_end = i + 2 + tag_len;

        // Vérification des limites pour éviter une lecture hors buffer
        if tag_end > data.len() { break; }

        // 0xDD = 221 = tag Vendor Specific
        if tag_id == 0xDD {
            let tag_data = &data[i + 2..tag_end];
            if tag_data.get(0..3) == Some(&DRONE_OUI) {
                return parse_drone_payload(tag_data);
            }
        }
        i = tag_end;
    }
    None
}

/// Recherche le tag SSID (type 0x00) dans les paramètres TLV
fn find_ssid(data: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 2 <= data.len() {
        let tag_id  = data[i];
        let tag_len = data[i + 1] as usize;
        let end     = i + 2 + tag_len;
        if end > data.len() { break; }

        if tag_id == 0x00 {
            return Some(
                String::from_utf8_lossy(&data[i + 2..end])
                    .trim().to_string()
            );
        }
        i = end;
    }
    None
}

/// Analyse les sous-tags du payload DroneID.
///
/// Structure des sous-tags (après OUI 3 octets + type 1 octet) :
/// - 0x01 : version du protocole
/// - 0x02 : identifiant du drone (30 octets ASCII)
/// - 0x04 : latitude  (i32 little-endian, à diviser par 100_000)
/// - 0x05 : longitude (i32 little-endian, à diviser par 100_000)
/// - 0x06 : altitude AMSL (i16 little-endian, en mètres)
/// - 0x0A : vitesse horizontale (u8, en m/s)
/// - 0x0B : cap (u16 little-endian, en degrés)
fn parse_drone_payload(data: &[u8]) -> Option<DroneFrame> {
    let mut drone_id  = String::new();
    let mac           = String::new(); // rempli plus tard par parse_drone_frame
    let ssid          = String::new(); // rempli plus tard par parse_drone_frame
    let mut latitude  = 0.0f32;
    let mut longitude = 0.0f32;
    let mut altitude  = 0i16;
    let mut speed     = 0u8;
    let mut heading   = 0u16;

    // On commence après l'OUI (3 octets) et le type OUI (1 octet)
    let mut i = 4;

    while i + 2 <= data.len() {
        let sub_id  = data[i];
        let sub_len = data[i + 1] as usize;
        let start   = i + 2;
        let end     = start + sub_len;
        if end > data.len() { break; }
        let val = &data[start..end];

        match sub_id {
            0x01 => { /* version — non utilisée */ }
            0x02 => {
                // Identifiant drone : chaîne ASCII de 30 octets
                drone_id = String::from_utf8_lossy(val)
                    .trim_matches('\0').trim().to_string();
            }
            0x04 => {
                // Latitude : entier signé 32 bits, divisé par 100_000
                if val.len() >= 4 {
                    let raw = i32::from_le_bytes(val[0..4].try_into().ok()?);
                    latitude = raw as f32 / 100_000.0;
                }
            }
            0x05 => {
                // Longitude : entier signé 32 bits, divisé par 100_000
                if val.len() >= 4 {
                    let raw = i32::from_le_bytes(val[0..4].try_into().ok()?);
                    longitude = raw as f32 / 100_000.0;
                }
            }
            0x06 => {
                // Altitude AMSL : entier signé 16 bits en mètres
                if val.len() >= 2 {
                    altitude = i16::from_le_bytes(val[0..2].try_into().ok()?);
                }
            }
            0x0A => {
                // Vitesse horizontale : 1 octet non signé
                if !val.is_empty() { speed = val[0]; }
            }
            0x0B => {
                // Cap : entier non signé 16 bits en degrés
                if val.len() >= 2 {
                    heading = u16::from_le_bytes(val[0..2].try_into().ok()?);
                }
            }
            _ => { /* sous-tag inconnu — ignoré sans erreur */ }
        }
        i = end;
    }

    // On rejette les trames sans identifiant drone
    if drone_id.is_empty() { return None; }
    Some(DroneFrame { drone_id, mac, ssid, latitude, longitude, altitude, speed, heading })
}