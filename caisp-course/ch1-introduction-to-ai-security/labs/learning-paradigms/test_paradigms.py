from aisec_lab import load_lab_module

P = load_lab_module(__file__, "paradigms")


def test_supervised_learns_and_generalizes():
    X, y = P.make_email_data()
    Xtr, ytr, Xte, yte = P.train_test_split(X, y)
    model = P.NearestCentroid().fit(Xtr, ytr)
    assert P.accuracy(yte, model.predict(Xte)) >= 0.95
    assert model.predict_one((5.0, 5.0)) == "spam"
    assert model.predict_one((0.5, 1.0)) == "ham"


def test_label_flipping_hurts_accuracy():
    X, y = P.make_email_data()
    Xtr, ytr, Xte, yte = P.train_test_split(X, y)
    clean = P.accuracy(yte, P.NearestCentroid().fit(Xtr, ytr).predict(Xte))
    poisoned = P.accuracy(yte, P.NearestCentroid().fit(Xtr, P.flip_labels(ytr, 0.5)).predict(Xte))
    assert poisoned < clean - 0.5
    # a few flipped labels are tolerated: the average barely moves
    mild = P.accuracy(yte, P.NearestCentroid().fit(Xtr, P.flip_labels(ytr, 0.1)).predict(Xte))
    assert mild >= 0.95


def test_poison_points_move_decision_boundary():
    X, y = P.make_email_data()
    # The attacker adds many "ham"-labelled points that sit in spam territory.
    Xp, yp = P.poison_with_points(X, y, n=200, label="ham", at=(5.0, 4.5))
    assert P.NearestCentroid().fit(Xp, yp).predict_one((4.0, 3.5)) == "ham"  # borderline spam now passes
    assert P.NearestCentroid().fit(X, y).predict_one((4.0, 3.5)) == "spam"


def test_kmeans_finds_two_groups_without_labels():
    X, y = P.make_email_data()
    _, assign = P.kmeans(X, k=2)
    agree = sum((a == 0) == (label == "ham") for a, label in zip(assign, y)) / len(y)
    assert max(agree, 1 - agree) > 0.95  # cluster ids are arbitrary, so allow swapped names


def test_anomaly_score_flags_outlier():
    X, _ = P.make_email_data()
    centroids, _ = P.kmeans(X, k=2)
    assert P.anomaly_score((30.0, 30.0), centroids) > 10 * P.anomaly_score((1.0, 1.0), centroids)


def test_bandit_prefers_best_arm():
    _, counts = P.epsilon_greedy(P.Bandit([0.2, 0.5, 0.8]))
    assert counts.index(max(counts)) == 2


def test_q_learning_reaches_goal():
    env = P.Corridor(n=6)
    assert P.greedy_path(env, P.q_learning(env)) == [0, 1, 2, 3, 4, 5]


def test_reward_hacking_with_bad_reward():
    # A bonus on state 1 that outweighs the goal makes the agent farm it forever.
    env = P.Corridor(n=6, bonus_state=1, bonus=0.8)
    path = P.greedy_path(env, P.q_learning(env, episodes=600), max_steps=20)
    assert path[-1] != 5  # never reaches the intended goal
    assert path.count(1) >= 5  # keeps bouncing on the bonus square


def test_precision_recall_f1():
    y_true = ["spam", "spam", "ham", "ham", "spam"]
    y_pred = ["spam", "ham", "ham", "spam", "spam"]
    p, r, f1 = P.precision_recall_f1(y_true, y_pred)
    assert round(p, 3) == round(2 / 3, 3) and round(r, 3) == round(2 / 3, 3) and round(f1, 3) == round(2 / 3, 3)


def test_accuracy_can_hide_a_useless_model():
    # 95% ham: a model that always says "ham" is 95% accurate and catches zero spam.
    y_true = ["ham"] * 95 + ["spam"] * 5
    y_pred = ["ham"] * 100
    assert P.accuracy(y_true, y_pred) == 0.95
    assert P.precision_recall_f1(y_true, y_pred)[1] == 0.0  # recall is zero


def test_overfitting_one_nn_memorises_training_but_generalizes_worse():
    X, y = P.make_noisy_data()
    Xtr, ytr, Xte, yte = P.train_test_split(X, y, seed=2)
    overfit = P.KNN(k=1).fit(Xtr, ytr)
    smooth = P.KNN(k=15).fit(Xtr, ytr)
    assert P.accuracy(ytr, overfit.predict(Xtr)) == 1.0  # perfect on data it has seen
    assert P.accuracy(yte, overfit.predict(Xte)) < P.accuracy(yte, smooth.predict(Xte))
