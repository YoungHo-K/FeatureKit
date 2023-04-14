import numpy as np


class Cumul:
    """
    Reference: https://github.com/lsvih/CUMUL
    """

    def __init__(self, number_of_features=100):
        self.number_of_features = number_of_features

        self.features = None

    def generate(self, packet_list):
        number_of_incoming_packet = 0
        number_of_outgoing_packet = 0
        size_of_total_incoming_packet = 0
        size_of_total_outgoing_packet = 0
        cumulative_packet_size_list = list()
        abs_cumulative_packet_size_list = list()

        packet_list.sort(key=lambda x: x.timestamp)
        for packet in packet_list:
            if packet.direction > 0:
                number_of_incoming_packet += 1
                size_of_total_incoming_packet += packet.packet_size
            else:
                number_of_outgoing_packet += 1
                size_of_total_outgoing_packet += packet.packet_size

            if len(cumulative_packet_size_list) == 0:
                cumulative_packet_size_list.append(packet.packet_size * packet.direction)
                abs_cumulative_packet_size_list.append(packet.packet_size)

            else:
                cumulative_packet_size_list.append(
                    cumulative_packet_size_list[-1] + packet.packet_size * packet.direction)
                abs_cumulative_packet_size_list.append(abs_cumulative_packet_size_list[-1] + packet.packet_size)

        features = list()
        features.append(number_of_incoming_packet)
        features.append(number_of_outgoing_packet)
        features.append(size_of_total_incoming_packet)
        features.append(size_of_total_outgoing_packet)

        features.extend(self._interpolate(cumulative_packet_size_list, abs_cumulative_packet_size_list))
        if len(features) != self.number_of_features + 4:
            return

        self.features = features

    def _interpolate(self, cumulative_packet_size_list, abs_cumulative_packet_size_list):
        interpolated_cumulative_packet_size_list = np.interp(
            np.linspace(abs_cumulative_packet_size_list[0], abs_cumulative_packet_size_list[-1],
                        self.number_of_features),
            abs_cumulative_packet_size_list,
            cumulative_packet_size_list)

        return list(interpolated_cumulative_packet_size_list)

    def get_string(self):
        if self.features is None:
            return None

        features = list()
        for index, value in enumerate(self.features):
            features.append(f"{index}:{value}")

        return " ".join(features)
