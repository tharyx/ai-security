"""Run from the repo root:
    .venv/Scripts/python caisp-course/ch1-introduction-to-ai-security/labs/learning-paradigms/demo.py
"""
import paradigms as P  # demo.py may import its sibling; tests use load_lab_module

X, y = P.make_email_data()
Xtr, ytr, Xte, yte = P.train_test_split(X, y)

print("== Supervised: nearest centroid ==")
m = P.NearestCentroid().fit(Xtr, ytr)
print("centroids:", {k: tuple(round(v, 2) for v in c) for k, c in m.centroids.items()})
print("clean test accuracy:", round(P.accuracy(yte, m.predict(Xte)), 3))
flipped = P.NearestCentroid().fit(Xtr, P.flip_labels(ytr, 0.5))
print("accuracy after 50% label flipping:", round(P.accuracy(yte, flipped.predict(Xte)), 3))
Xp, yp = P.poison_with_points(X, y, n=200, label="ham", at=(5.0, 4.5))
print("borderline spam email (4.0, 3.5): clean model says", P.NearestCentroid().fit(X, y).predict_one((4.0, 3.5)),
      "| poisoned model says", P.NearestCentroid().fit(Xp, yp).predict_one((4.0, 3.5)))

print("\n== Unsupervised: k-means (no labels used) ==")
cents, assign = P.kmeans(X, k=2)
print("centres:", [tuple(round(v, 2) for v in c) for c in cents])
print("anomaly score normal (1,1):", round(P.anomaly_score((1, 1), cents), 2),
      "| odd (30,30):", round(P.anomaly_score((30, 30), cents), 2))

print("\n== Reinforcement: bandit ==")
values, counts = P.epsilon_greedy(P.Bandit([0.2, 0.5, 0.8]))
print("estimated values:", [round(v, 2) for v in values], "pull counts:", counts)

print("\n== Reinforcement: Q-learning corridor ==")
env = P.Corridor(n=6)
print("greedy path:", P.greedy_path(env, P.q_learning(env)))
bad = P.Corridor(n=6, bonus_state=1, bonus=0.8)
print("path with a badly designed bonus reward:", P.greedy_path(bad, P.q_learning(bad, episodes=600)))

print("\n== Metrics and overfitting ==")
yt = ["ham"] * 95 + ["spam"] * 5
print("always-ham model: accuracy", P.accuracy(yt, ["ham"] * 100), "| precision/recall/F1 for spam:",
      tuple(round(v, 2) for v in P.precision_recall_f1(yt, ["ham"] * 100)))
Xn, yn = P.make_noisy_data()
a, b, c, d = P.train_test_split(Xn, yn, seed=2)
for k in (1, 15):
    m = P.KNN(k).fit(a, b)
    print(f"k={k:2}: train accuracy {P.accuracy(b, m.predict(a)):.2f} | test accuracy {P.accuracy(d, m.predict(c)):.2f}")
