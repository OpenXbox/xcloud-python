from typing import List, Tuple


from aiortc import (
    RTCIceGatherer,
    RTCIceCandidate,
    RTCIceTransport,
    RTCIceParameters
)


class ICEHandler:
    Full: int = 1
    PacingMs: int = 50
    Version: int = 1

    def __init__(self):
        self._gatherer = RTCIceGatherer()
        self._transport = RTCIceTransport(self._gatherer)

    @property
    def transport(self) -> RTCIceTransport:
        return self._transport

    @staticmethod
    def _candidate_to_dict(candidate: RTCIceCandidate) -> dict:
        return {
            "transportAddress": f"{candidate.ip}:{candidate.port}",
            "baseAddress": f"{candidate.ip}:{candidate.port}",
            "serverAddress": "",
            "ipv6": "0",
            "type": "0",
            "addressType": "3",  # TODO: whats addressType ?
            "priority": str(candidate.priority),
            "foundation": candidate.foundation,
            "transport": candidate.protocol
        }

    @staticmethod
    def _dict_to_candidate(candidate_node: dict) -> RTCIceCandidate:
        host_port_combo: str = candidate_node.get('transportAddress')
        candidate_type: str = candidate_node.get('type')
        priority: int = int(candidate_node.get('priority'))
        foundation: str = candidate_node.get('foundation')
        protocol: str = candidate_node.get('transport')

        # TODO: whats component?
        component = 0

        host, port = host_port_combo.rsplit(':', maxsplit=1)

        return RTCIceCandidate(
            component, foundation, host, port, priority, protocol,
            candidate_type
        )

    async def generate_local_config(self) -> dict:
        await self._gatherer.gather()
        local_candidates = self._gatherer.getLocalCandidates()
        local_params = self._gatherer.getLocalParameters()

        ice_config: dict = {
            "Full": str(ICEHandler.Full),
            "PacingMs": str(ICEHandler.PacingMs),
            "Version": str(ICEHandler.Version),
            "Username": local_params.usernameFragment,
            "Password": local_params.password,
            "Candidates": {
                "count": str(len(local_candidates))
            }
        }
        for index, candidate in enumerate(local_candidates):
            candidate_node = ICEHandler._candidate_to_dict(candidate)
            ice_config['Candidates'].update({
                str(index): candidate_node
            })

        return ice_config

    @staticmethod
    def parse_remote_config(
        ice_config: dict
    ) -> Tuple[List[RTCIceCandidate], RTCIceParameters]:
        candidate_nodes: dict = ice_config.get('Candidates')
        if not candidate_nodes:
            raise Exception(
                'parse_remote_config: Invalid input, no Candidates node found'
            )

        remote_params = RTCIceParameters(
            ice_config.get('Username'),
            ice_config.get('Password')
        )

        candidates: List[RTCIceCandidate] = []
        candidate_count = int(candidate_nodes.get('count'))
        for i in range(candidate_count):
            candidate_node: dict = candidate_nodes.get(str(i))
            candidate = ICEHandler._dict_to_candidate(candidate_node)
            candidates.append(candidate)

        return candidates, remote_params
