
from traffic_fingerprinting.utils.statistics import get_statistics


class Concentration:
    def __init__(self, chunk_size=20):
        self.chunk_size = chunk_size

        self.features = None

    def fit(self, packet_list):
        outgoing_concentration_list = self._get_outgoing_concentration(packet_list)

        features = list()
        features.extend(get_statistics(outgoing_concentration_list))

        self.features = features

    def _get_outgoing_concentration(self, packet_list):
        packet_list.sort(key=lambda x: x.timestamp)

        outgoing_concentration_list = list()
        for index in range(0, len(packet_list) - self.chunk_size + 1, self.chunk_size):
            chunk = packet_list[index: index + self.chunk_size]

            number_of_outgoing_packets_in_chunk = 0
            for packet in chunk:
                number_of_outgoing_packets_in_chunk += 1 if packet.direction < 0 else 0

            outgoing_concentration_list.append(number_of_outgoing_packets_in_chunk)

        return outgoing_concentration_list

    def get_string(self):
        if self.features is None:
            return None

        features = list()
        for index, value in enumerate(self.features):
            features.append(f"{index}:{value}")

        return " ".join(features)
