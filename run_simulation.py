from core.dataset_loader import load_dataset
from core.simulation_engine import simulate_scenario
import random


scenarios = load_dataset()

# pick random scenario
scenario = random.choice(scenarios)

simulate_scenario(scenario)