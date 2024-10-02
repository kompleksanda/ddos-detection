import simpy
import math
import random
from collections import Counter

# The packet object
class Packet(object):
    def __init__(self, time, size, id, src="198.13.4.22", dst="127.0.0.1"):
        self.time = time
        self.size = size
        self.id = id
        self.src = src
        self.dst = dst

    def __repr__(self):
        return "id: {}, src: {}, time: {}, size: {}".\
            format(self.id, self.src, self.time, self.size)

# packet generator nodes
class PacketGenerator(object):
    def __init__(self, env, id,  adist, sdist, initial_delay=0, finish=float("inf")):
        self.id = id
        self.env = env
        self.adist = adist
        self.sdist = sdist
        self.initial_delay = initial_delay
        self.finish = finish
        self.out = None
        self.packets_sent = 0
        self.action = env.process(self.run())

    def run(self):
        yield self.env.timeout(self.initial_delay)
        while self.env.now < self.finish:
            yield self.env.timeout(self.adist())
            self.packets_sent += 1
            p = Packet(self.env.now, self.sdist(), self.packets_sent, src=self.id)
            self.out.put(p)

#The end points of all pkt, to collect statistics
class PacketSink(object):
    def __init__(self, env, rec_arrivals=False, absolute_arrivals=False, rec_waits=True, debug=False, selector=None, entropy_window=10, entropy_time_window=5):
        self.store = simpy.Store(env)
        self.env = env
        self.rec_waits = rec_waits
        self.rec_arrivals = rec_arrivals
        self.absolute_arrivals = absolute_arrivals
        self.waits = []
        self.arrivals = []
        self.debug = debug
        self.packets_rec = 0
        self.bytes_rec = 0
        self.selector = selector
        self.last_arrival = 0.0 #
        self.ip_list = []
        self.all_ip = []
        self.time = []
        self.wait = 0
        self.average_wait = []
        self.entropy_counter = 0
        self.ddos_detected = False
        self.entropy_window = entropy_window
        self.entropy_time_window = entropy_time_window
        self.packet_box = {}
        self.entropies = [1]

    def put(self, pkt):
        if not self.selector or self.selector(pkt):
            now = self.env.now
            self.time.append(now)
            if pkt.src not in self.packet_box:
                self.packet_box[pkt.src] = {"waits": [], "arrivals": [], "packets_rec": [1], "average_wait":[], "time":[now], "arrival_rate":[], "last_arrival":now}
            else:
                self.packet_box[pkt.src]["time"].append(now)
                self.packet_box[pkt.src]["packets_rec"].append(self.packet_box[pkt.src]["packets_rec"][-1]+1)
            if self.rec_waits:
                self.waits.append(self.env.now - pkt.time)
                self.average_wait.append(sum(self.waits)/len(self.waits))
                self.packet_box[pkt.src]["waits"].append(now - pkt.time)
                self.packet_box[pkt.src]["average_wait"].append(sum(self.packet_box[pkt.src]["waits"])/len(self.packet_box[pkt.src]["waits"]))
            if self.rec_arrivals:
                if self.absolute_arrivals:
                    self.arrivals.append(now)
                    self.packet_box[pkt.src]["arrivals"].append(now)
                else:
                    self.arrivals.append(now - self.last_arrival)
                    self.packet_box[pkt.src]["arrivals"].append(now - self.packet_box[pkt.src]["last_arrival"])
                self.packet_box[pkt.src]["arrival_rate"].append(sum(self.packet_box[pkt.src]["arrivals"])/len(self.packet_box[pkt.src]["arrivals"]))
                self.last_arrival = now
                self.packet_box[pkt.src]["last_arrival"] = now
            self.packets_rec += 1
            self.bytes_rec += pkt.size
            if self.debug:
                print(pkt)
            #return self.get_entropy(pkt)
            self.get_entropy_time(pkt, now)

    def get_entropy(self, packet=None):
        if not packet:
            return self.entropies[-1]
        self.ip_list.append(packet.src)
        if packet.src not in self.all_ip: self.all_ip.append(packet.src)
        if len(self.ip_list) == self.entropy_window:
            entropy_list = []
            counter = Counter(self.ip_list)
            for count in counter.values():
                probability = abs(count/self.entropy_window)
                ip_entropy = -probability * math.log(probability, 2)
                entropy_list.append(ip_entropy)
            entropy = sum(entropy_list)
            len_all_ip = len(self.all_ip)
            N0 = math.log(len_all_ip, 2)
            if N0 == 0:
                #raise ValueError("Num of packet generator must be greater than 1")
                normed = 1
            else: normed = entropy/N0
            #print("Normed=", normed)
            self.entropies.append(normed)
            if normed < 0.5:
                self.entropy_counter += 1
                self.wait = 3
            else:
                if not self.wait:
                    self.entropy_counter = 0
                else:
                    self.wait -= 1
            if self.entropy_counter > 10:
                self.ddos_detected = True
                #print("------------------------------")
                #print("DDoS attack detected!")
                #print("------------------------------")
                self.entropy_counter = 0
            self.ip_list = self.ip_list[1:]
        else:     
            self.entropies.append(self.entropies[-1])

    def get_entropy_time(self, packet=None, now=None):
        if not packet:
            return self.entropies[-1]
        self.ip_list.append(packet.src)
        if packet.src not in self.all_ip: self.all_ip.append(packet.src)
        if len(self.ip_list) < self.entropy_window:
            self.entropies.append(self.entropies[-1])
        index = -1
        if self.absolute_arrivals:
            end = now - self.entropy_time_window
            for arr in self.arrivals[::-1][:-1]:
                if arr >= end:
                    index -= 1
                else: break
        else:
            total_time = 0
            for arr in self.arrivals[::-1]:
                total_time += arr
                if total_time <= self.entropy_time_window:
                    index -= 1
                else: break
        self.ip_list = self.ip_list[index:]
        if len(self.ip_list) == self.entropy_window:
            entropy = 0
            counter = Counter(self.ip_list)
            for count in counter.values():
                probability = abs(count/self.entropy_window)
                ip_entropy = -probability * math.log(probability, 2)
                entropy += ip_entropy
            N0 = math.log(len(self.all_ip), 2)
            if N0 == 0:
                #raise ValueError("Num of packet generator must be greater than 1")
                normed = 1
            else: normed = entropy/N0
            self.entropies.append(normed)
            if normed < 0.5:
                self.entropy_counter += 1
            else: 
                self.entropy_counter = 0
            if self.entropy_counter > 10:
                self.ddos_detected = True
                #print("------------------------------")
                #print("DDoS attack detected!")
                #print("------------------------------")
                #self.entropy_counter = 0
            self.ip_list = self.ip_list[1:]
        else:
            self.entropies.append(self.entropies[-1])


# A switch port
class SwitchPort(object):
    def __init__(self, env, rate, qlimit=None, limit_bytes=False, debug=False):
        self.store = simpy.Store(env)
        self.rate = rate
        self.env = env
        self.out = None
        self.packets_rec = 0
        self.packets_drop = 0
        self.qlimit = qlimit
        self.limit_bytes = limit_bytes
        self.byte_size = 0
        self.debug = debug
        self.busy = 0
        self.action = env.process(self.run()) #run on start
        self.rec_rate = []
        self.time = []
        self.buffer_size = []
        self.dropped_packets = []
        self.dropped_arrivals = []
        self.dropped_time_window = 100
        self.entropy_detected = False
        self.packet_box = {}
        self.entropies = [1]

    def run(self):
        while True:
            msg = (yield self.store.get())
            self.busy = 1
            self.byte_size -= msg.size
            yield self.env.timeout(msg.size*8.0/self.rate)
            self.out.put(msg)
            self.busy = 0
            if self.debug:
                print(msg)

    def put(self, pkt):
        self.packets_rec += 1
        now = self.env.now
        if pkt.src not in self.packet_box:
            self.packet_box[pkt.src] = {"rec_rate":[], "time":[now], "packets_rec": [1]}
            self.packet_box[pkt.src]["rec_rate"].append(1/now)
        else:
            self.packet_box[pkt.src]["time"].append(now)
            self.packet_box[pkt.src]["packets_rec"].append(self.packet_box[pkt.src]["packets_rec"][-1]+1)
            self.packet_box[pkt.src]["rec_rate"].append(self.packet_box[pkt.src]["packets_rec"][-1]/now)
        self.rec_rate.append(self.packets_rec/now)
        self.time.append(now)
        self.buffer_size.append(len(self.store.items))
        tmp_byte_count = self.byte_size + pkt.size

        if self.qlimit is None:
            self.byte_size = tmp_byte_count
            self.trim_dropped(now)
            self.entropies.append(self.calc_entropy(self.dropped_packets))
            return self.store.put(pkt)
        if self.limit_bytes and tmp_byte_count >= self.qlimit:
            self.packets_drop += 1
            self.dropped_packets.append(pkt.src)
            self.dropped_arrivals.append(now)
            self.trim_dropped(now)
            self.check_entropy()
        elif not self.limit_bytes and len(self.store.items) >= self.qlimit:
            self.packets_drop += 1
            self.dropped_packets.append(pkt.src)
            self.dropped_arrivals.append(now)
            self.trim_dropped(now)
            self.check_entropy()
        else:
            self.byte_size = tmp_byte_count
            self.trim_dropped(now)
            self.entropies.append(self.calc_entropy(self.dropped_packets))
            return self.store.put(pkt)
    
    def trim_dropped(self, now):
        index = -1
        end = now - self.dropped_time_window
        for arr in self.dropped_arrivals[::-1][:-1]:
            if arr >= end:
                index -= 1
            else: break
        self.dropped_packets = self.dropped_packets[index:]
        self.dropped_arrivals = self.dropped_arrivals[index:]
            
    def check_entropy(self):
        if not self.dropped_packets:
            self.entropies.append(self.entropies[-1])
            return
        values = Counter(self.dropped_packets).values()
        length = sum(values)
        if length > self.qlimit:
            #print(self.dropped_packets)
            entropy_list = []
            for i in values:
                probability = abs(i/length)
                ip_entropy = -probability * math.log(probability, 2)
                entropy_list.append(ip_entropy)
            entropy = sum(entropy_list)
            N0 = math.log(length, 2)
            entropy = entropy/N0
            self.entropies.append(entropy)
            if entropy < 0.5:
                if not self.entropy_detected:
                    print("---------------------------")
                    print("DDoS attack detectedd")
                    print("---------------------------")
                    self.entropy_detected = True
        else:
            self.entropies.append(self.out.get_entropy())
            #self.entropies.append(self.entropies[-1])
    def calc_entropy(self, queue):
        values = Counter(queue).values()
        if not values:
            return self.out.get_entropy()
            #return self.entropies[-1]
        length = sum(values)
        entropy_list = []
        for i in values:
            probability = abs(i/length)
            ip_entropy = -probability * math.log(probability, 2)
            entropy_list.append(ip_entropy)
        entropy = sum(entropy_list)
        N0 = math.log(length, 2)
        if N0 == 0:
            return self.out.get_entropy()
            #return self.entropies[-1]
        entropy = entropy/N0
        return entropy