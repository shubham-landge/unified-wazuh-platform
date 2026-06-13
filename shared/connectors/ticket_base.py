from abc import ABC, abstractmethod


class TicketConnector(ABC):

    @abstractmethod
    async def create_ticket(self, case_data: dict) -> dict:
        pass

    @abstractmethod
    async def update_ticket(self, remote_id: str, case_data: dict) -> dict:
        pass

    @abstractmethod
    async def get_ticket(self, remote_id: str) -> dict:
        pass

    @abstractmethod
    async def health(self) -> dict:
        pass
