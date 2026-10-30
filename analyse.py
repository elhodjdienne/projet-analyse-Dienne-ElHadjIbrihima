"""Analyse des journaux d'un pare-feu - Projet 1 (Réseaux / Sécurité / IoT).

Usage : python analyse.py
Lit data/logs_reseau.csv, nettoie, calcule les résultats,
enregistre les figures dans figures/ et écrit resultats.json.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas d'affichage nécessaire
import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).resolve().parent
CSV = BASE / "data" / "logs_reseau.csv"
FIG_DIR = BASE / "figures"
FIG_DIR.mkdir(exist_ok=True)

PORTS = {22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS", 1883: "MQTT"}


def nettoyer(df):
    """Doublons exacts, protocol en majuscules, médiane pour bytes_sent."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculée après suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer(df):
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def sauver(nom):
    plt.tight_layout()
    plt.savefig(FIG_DIR / nom, dpi=120)
    plt.close()


def figures(df):
    # 1. Top 10 des ports de destination
    top = df["dst_port"].value_counts().head(10)
    labels = [f"{p}\n{PORTS[p]}" if p in PORTS else str(p) for p in top.index]
    plt.figure(figsize=(9, 5))
    plt.bar(labels, top.values, color="steelblue")
    plt.title("Top 10 des ports de destination")
    plt.xlabel("Port de destination")
    plt.ylabel("Nombre de connexions")
    sauver("top_ports.png")

    # 2. Connexions par jour
    par_jour = df.groupby(df["timestamp"].dt.date).size()
    plt.figure(figsize=(9, 5))
    plt.bar([str(d) for d in par_jour.index], par_jour.values, color="teal")
    plt.title("Nombre de connexions par jour")
    plt.xlabel("Date")
    plt.ylabel("Nombre de connexions")
    plt.xticks(rotation=45)
    sauver("connexions_par_jour.png")

    # 3. Connexions par heure
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    plt.figure(figsize=(9, 5))
    plt.plot(par_heure.index, par_heure.values, marker="o", color="darkorange")
    plt.title("Connexions par heure de la journée")
    plt.xlabel("Heure (0-23)")
    plt.ylabel("Nombre de connexions")
    plt.xticks(range(0, 24))
    plt.grid(alpha=0.3)
    sauver("connexions_par_heure.png")

    # 4. Volume d'octets par type d'appareil
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    plt.figure(figsize=(8, 5))
    plt.bar(vol.index, vol.values / 1e6, color="seagreen")
    plt.title("Volume d'octets envoyés par type d'appareil")
    plt.xlabel("Type d'appareil")
    plt.ylabel("Volume total (Mo)")
    sauver("octets_par_appareil.png")

    # 5. Répartition ALLOW / DENY
    rep = df["action"].value_counts()
    plt.figure(figsize=(6, 6))
    plt.pie(rep.values, labels=rep.index, autopct="%1.1f%%",
            colors=["#4caf50", "#e53935"][: len(rep)], startangle=90)
    plt.title("Répartition ALLOW / DENY")
    sauver("repartition_allow_deny.png")

    # 6. Ports distincts contactés par source (top 10)
    sc = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    plt.figure(figsize=(9, 5))
    plt.barh(sc.index[::-1], sc.values[::-1], color="firebrick")
    plt.title("Ports distincts contactés par adresse source (top 10)")
    plt.xlabel("Nombre de ports distincts")
    plt.ylabel("Adresse IP source")
    sauver("ports_distincts_par_ip.png")

    # 7. Octets envoyés par IP source (top 10)
    ex = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)
    plt.figure(figsize=(9, 5))
    plt.barh(ex.index[::-1], ex.values[::-1] / 1e6, color="purple")
    plt.title("Volume total d'octets envoyés par IP source (top 10)")
    plt.xlabel("Volume total (Mo)")
    plt.ylabel("Adresse IP source")
    sauver("octets_par_ip.png")


def main():
    df = nettoyer(pd.read_csv(CSV))
    resultats = calculer(df)
    figures(df)
    with open(BASE / "resultats.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(json.dumps(resultats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
