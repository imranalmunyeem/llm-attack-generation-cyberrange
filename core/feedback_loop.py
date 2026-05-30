import random


class DefenderFeedbackLoop:

    def __init__(self):
        self.defense_strength = 0.6  # initial SOC strength

    def update_defense(self, detection_rate):

        """
        SOC adapts based on attack detection performance
        """

        if detection_rate < 0.5:
            self.defense_strength += 0.1  # improve defenses
        elif detection_rate > 0.8:
            self.defense_strength -= 0.05  # attackers evolving faster

        self.defense_strength = max(0.2, min(0.95, self.defense_strength))

        return self.defense_strength

    def adaptive_detection(self, technique_id):

        """
        Detection probability evolves over time
        """

        base_prob = 0.6

        # hard techniques remain harder
        hard = ["T1595", "T1203", "T1021", "T1041"]

        if technique_id in hard:
            base_prob -= 0.2

        # SOC improvement effect
        base_prob += (self.defense_strength - 0.5)

        return max(0.1, min(0.95, base_prob))


if __name__ == "__main__":

    loop = DefenderFeedbackLoop()

    print("Initial defense strength:", loop.defense_strength)

    loop.update_defense(0.4)
    print("Updated defense strength:", loop.defense_strength)

    print("Detection probability T1566:", loop.adaptive_detection("T1566"))