"""
HAQIQIY dataset (TON_IoT Network, UNSW Canberra) bilan Random Forest o'qitish.

Dataset manbai (GitHub): PatrickYanZihui/TON_IOT_Intrusion_Detection -> rawDataSet/Train_Test_Network.csv
Asl dataset: Moustafa, N. "ToN_IoT datasets" (UNSW Canberra). Akademik foydalanish uchun, manbani keltiring.

Ishga tushirish:  python train_real.py
"""
import os, json, time, urllib.request
import joblib, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support, confusion_matrix,
                             classification_report, ConfusionMatrixDisplay)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "Train_Test_Network.csv")
URL = ("https://raw.githubusercontent.com/PatrickYanZihui/TON_IOT_Intrusion_Detection/"
       "b95dbc38c7cce95dfb974fb9c516c6f042c3fab4/rawDataSet/Train_Test_Network.csv")   # aniq commit: shox nomi o'zgarsa ham ishlaydi
SEED = 42


def load():
    if not os.path.exists(DATA):
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        print("[+] Dataset yuklab olinmoqda (~67 MB), biroz kuting...")
        try:
            urllib.request.urlretrieve(URL, DATA)
        except Exception as e:
            if os.path.exists(DATA):
                os.remove(DATA)
            raise SystemExit(f"Yuklab bo'lmadi: {e}\nQo'lda yuklang: {URL}\nva faylni shu yerga qo'ying: {DATA}")
    df = pd.read_csv(DATA, low_memory=False)
    print(f"[+] Yuklandi: {df.shape[0]:,} oqim, {df.shape[1]} ustun")
    return df


def make_features(df):
    """Faqat oqim xususiyatlari. IP manzillar va vaqt (ts) ATAYIN ishlatilmaydi:
    ular hujum sessiyasini 'yodlab olish'ga (data leakage) olib keladi."""
    out = pd.DataFrame(index=df.index)
    out["duration"] = df["duration"]
    out["bytes_sent"] = df["src_bytes"]
    out["bytes_received"] = df["dst_bytes"]
    out["packets_sent"] = df["src_pkts"]
    out["packets_received"] = df["dst_pkts"]
    out["packet_size"] = df["src_ip_bytes"] / df["src_pkts"].clip(lower=1)           # o'rtacha paket hajmi
    out["packet_rate"] = df["src_pkts"] / df["duration"].clip(lower=1e-3)            # paket/soniya
    out["missed_bytes"] = df["missed_bytes"]
    out["dst_port"] = df["dst_port"]
    for c in ["proto", "service", "conn_state"]:                                      # kategorik -> raqam
        out[c] = df[c].astype("category").cat.codes
    return out


def main():
    t0 = time.time()
    df = load()
    n0 = len(df)
    df = df.drop_duplicates(subset=[c for c in df.columns if c not in ("ts",)]).reset_index(drop=True)
    print(f"[+] Dublikatlar olib tashlandi: {n0 - len(df):,} ta. Qoldi: {len(df):,}")
    X, y = make_features(df), df["type"]
    classes = sorted(y.unique())
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    print(f"[+] Train: {len(Xtr):,}  Test: {len(Xte):,}  Sinflar: {classes}")

    # --- Baseline modellar bilan solishtirish ---
    results = {}
    sc = StandardScaler().fit(Xtr)
    models = {
        "Logistic Regression": (LogisticRegression(max_iter=300, n_jobs=-1), True),
        "Decision Tree": (DecisionTreeClassifier(max_depth=20, random_state=SEED), False),
        "Random Forest": (RandomForestClassifier(n_estimators=100, max_depth=25, min_samples_leaf=2,
                                                 class_weight="balanced_subsample", n_jobs=-1,
                                                 random_state=SEED), False),
    }
    fitted = {}
    for name, (m, scaled) in models.items():
        t = time.time()
        m.fit(sc.transform(Xtr) if scaled else Xtr, ytr)
        pred = m.predict(sc.transform(Xte) if scaled else Xte)
        p, r, f, _ = precision_recall_fscore_support(yte, pred, average="macro", zero_division=0)
        results[name] = dict(accuracy=accuracy_score(yte, pred), precision=p, recall=r, f1=f,
                             seconds=round(time.time() - t, 1))
        fitted[name] = (m, pred)
        print(f"  {name:20s} acc={results[name]['accuracy']:.4f}  P={p:.4f}  R={r:.4f}  F1={f:.4f}  ({results[name]['seconds']}s)")

    rf, pred = fitted["Random Forest"]
    print("\n=== Random Forest: sinflar bo'yicha ===")
    print(classification_report(yte, pred, digits=4, zero_division=0))

    # --- Ikkilik (Normal vs Hujum) ---
    yb, pb = (yte != "normal"), (pd.Series(pred, index=yte.index) != "normal")
    tp, fn, fp, tn = ((yb & pb).sum(), (yb & ~pb).sum(), (~yb & pb).sum(), (~yb & ~pb).sum())
    binary = dict(detection_rate=tp / (tp + fn), false_alarm_rate=fp / (fp + tn),
                  precision=tp / (tp + fp), missed_attacks=int(fn), false_alarms=int(fp))
    print("Ikkilik (Normal/Hujum):", {k: round(float(v), 4) for k, v in binary.items()})

    # --- Saqlash ---
    cm = confusion_matrix(yte, pred, labels=classes)
    imp = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("\nFeature importance:\n", imp.round(3).to_string())
    fig, ax = plt.subplots(figsize=(9, 8))
    ConfusionMatrixDisplay(cm, display_labels=classes).plot(ax=ax, cmap="Blues", colorbar=False, xticks_rotation=45)
    ax.set_title("Confusion Matrix - TON_IoT Network (Random Forest)")
    plt.tight_layout(); plt.savefig(os.path.join(HERE, "real_confusion_matrix.png"), dpi=130); plt.close()
    fig, ax = plt.subplots(figsize=(7, 5))
    imp.sort_values().plot(kind="barh", ax=ax, color="#0f766e"); ax.set_title("Feature importance")
    plt.tight_layout(); plt.savefig(os.path.join(HERE, "real_feature_importance.png"), dpi=130); plt.close()
    summary = dict(dataset="TON_IoT Network", n_flows=int(len(df)), classes=classes, comparison=results,
                   binary={k: float(v) for k, v in binary.items()}, confusion_matrix=cm.tolist(),
                   importance={k: float(v) for k, v in imp.items()})
    json.dump(summary, open(os.path.join(HERE, "real_results.json"), "w"), indent=2)
    # Kategorik kodlar jadvali: real trafikni modelga AYNAN shu kodlar bilan berish uchun saqlanadi
    cats = {c: [str(v) for v in df[c].astype("category").cat.categories] for c in ["proto", "service", "conn_state"]}
    joblib.dump({"model": rf, "features": list(X.columns), "classes": classes, "categories": cats},
                os.path.join(HERE, "model_real.joblib"), compress=3)

    # --- LIVE model: portga/servisga bog'liq emas (real tarmoqda yolg'on signal kamroq) ---
    live_cols = [c for c in X.columns if c not in ("dst_port", "service")]
    rfl = RandomForestClassifier(n_estimators=100, max_depth=25, min_samples_leaf=2,
                                 class_weight="balanced_subsample", n_jobs=-1, random_state=SEED).fit(Xtr[live_cols], ytr)
    pl = rfl.predict(Xte[live_cols])
    lp, lr, lf, _ = precision_recall_fscore_support(yte, pl, average="macro", zero_division=0)
    print(f"\nLIVE model (dst_port/service yo'q): acc={accuracy_score(yte, pl):.4f} P={lp:.4f} R={lr:.4f} F1={lf:.4f}")
    summary["live_model"] = dict(accuracy=accuracy_score(yte, pl), precision=lp, recall=lr, f1=lf, features=live_cols)
    json.dump(summary, open(os.path.join(HERE, "real_results.json"), "w"), indent=2)
    joblib.dump({"model": rfl, "features": live_cols, "classes": classes, "categories": cats},
                os.path.join(HERE, "model_live.joblib"), compress=3)
    print(f"\n[+] Tayyor ({time.time() - t0:.0f}s). Saqlandi: real_results.json, real_*.png, model_real.joblib, model_live.joblib")


if __name__ == "__main__":
    main()
