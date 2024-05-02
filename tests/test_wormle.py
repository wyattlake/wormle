from ape import accounts, project, chain
from ape.contracts import ContractInstance
import pytest

@pytest.fixture
def owner(accounts) -> ContractInstance:
    return accounts[0]

@pytest.fixture
def game_contract(owner) -> ContractInstance:
    deployed_contract = owner.deploy(project.Game)
    return deployed_contract