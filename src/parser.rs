//! # Module parser
//! Contient toutes les fonctions d'analyse des trames WiFi 802.11.
//! Permet d'extraire les informations des trames beacon normales
//! et des trames DroneID conformes à la réglementation française.

use serde::Serialize;

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

/// Décode le tag Vendor Specific (221) DroneID français (6A:5C:35)
/// avec remoteid::france (valeurs big-endian, arrêté du 27 décembre 2019)
fn find_drone_tag(data: &[u8]) -> Option<DroneFrame> {
    let b = remoteid::france::find_in_elements(data)?;
    let drone_id = b.identifier_str()?.trim().to_string();
    if drone_id.is_empty() { return None; }
    Some(DroneFrame {
        drone_id,
        mac:       String::new(), // rempli plus tard par parse_drone_frame
        ssid:      String::new(), // rempli plus tard par parse_drone_frame
        latitude:  b.latitude.unwrap_or(0.0) as f32,
        longitude: b.longitude.unwrap_or(0.0) as f32,
        altitude:  b.altitude.unwrap_or(0),
        speed:     b.horizontal_speed.unwrap_or(0),
        heading:   b.true_course.unwrap_or(0),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_french_beacon_big_endian() {
        // Valeurs de capture-23-05-08-ttgo.pcapng ; Radiotap (8) + 802.11 (24) + champs fixes (12)
        let mut pkt = vec![0u8, 0, 8, 0, 0, 0, 0, 0];
        let mut hdr = vec![0u8; 36];
        hdr[0] = 0x80;
        hdr[10..16].copy_from_slice(&[0x24, 0x62, 0xab, 0xdd, 0xb0, 0xbd]);
        pkt.extend(hdr);
        pkt.extend([0x00, 4, b'T', b'E', b'S', b'T']);
        let mut v = vec![0x6A, 0x5C, 0x35, 0x01, 0x01, 1, 1, 0x02, 30];
        v.extend(b"000ENSEATHESEUS202300000000001");
        v.extend([0x04, 4]); v.extend(4_918_493i32.to_be_bytes());
        v.extend([0x05, 4]); v.extend(241_255i32.to_be_bytes());
        v.extend([0x06, 2]); v.extend(133i16.to_be_bytes());
        v.extend([0x0A, 1, 7]);
        v.extend([0x0B, 2]); v.extend(270u16.to_be_bytes());
        pkt.extend([0xDD, v.len() as u8]);
        pkt.extend(v);

        let d = parse_drone_frame(&pkt).unwrap();
        assert_eq!(d.drone_id, "000ENSEATHESEUS202300000000001");
        assert!((d.latitude - 49.18493).abs() < 1e-4);
        assert!((d.longitude - 2.41255).abs() < 1e-4);
        assert_eq!(d.altitude, 133);
        assert_eq!(d.speed, 7);
        assert_eq!(d.heading, 270);
    }
}
