from SimulationComponents import PacketGenerator, PacketSink, SwitchPort
import functools
import simpy
import random
import matplotlib.pyplot as plt
import PySimpleGUI as sg

layout = [
            [sg.Text("How many packet generators nodes"), sg.In(size=(3, 1), enable_events=True, default_text="5", key="-NUMPACKETSGEN-")],
            [sg.Text("Number of attacker nodes"), sg.In(size=(3, 1), default_text="2", enable_events=True, key="-NUMATTNODES-")],
            [sg.Text("Nodes Start IP"), sg.In(size=(15, 1), enable_events=True, default_text="10.0.0.1", key="-STARTIP-")],
            [sg.HorizontalSeparator(pad=None, color='Black')],
            [sg.Text("Normal arrival rates within"), sg.In(size=(3, 1), default_text="5", enable_events=True, key="-ARRIVALRATE-")],
            [sg.Text("Attacker arrival rates within"), sg.In(size=(3, 1), default_text="0.5", enable_events=True, key="-ATTARRIVALRATE-")],
            [sg.HorizontalSeparator(pad=None, color='Black')],
            [sg.Text("Run for"), sg.In(size=(5, 1), enable_events=True, default_text="1000", key="-RUNTIME-")],
            [sg.Text("Time to start attack"), sg.In(size=(4, 1), default_text="300", enable_events=True, key="-ATTACKTIME-")],
            [sg.Text("Time to end attack"), sg.In(size=(4, 1), default_text="700", enable_events=True, key="-ATTACKENDTIME-")],
            [sg.HorizontalSeparator(pad=None, color='Black')],
            [sg.Text("Packet size within"), sg.In(size=(3, 1), default_text="200", enable_events=True, key="-PACKETSIZE-")],
            [sg.Text("Switch port rate"), sg.In(size=(3, 1), enable_events=True, default_text="2", key="-PORTRATE-")],
            [sg.Text("Buffer size"), sg.In(size=(3, 1), enable_events=True, default_text="10", key="-BUFFERSIZE-")],
            [sg.HorizontalSeparator(pad=None, color='Black')],
            [sg.Text("Entropy window"), sg.In(size=(3, 1), enable_events=True, default_text="10", key="-ENTROPYWIN-")],
            [sg.Text("Entropy time window"), sg.In(size=(3, 1), enable_events=True, default_text="5", key="-ENTROPYTIMEWIN-")],
            [sg.Button("OK"), sg.Cancel()],
        ]

window = sg.Window("Entropy", layout, margins=(100, 50))

def plot_entropy(switch_port, density=False):
    axis = plt.subplots()[1]
    if density:
        axis.hist(switch_port.entropies[1:], 200, density=True,  label="density")
        axis.set_title("Entropy density distribution")
        axis.set_xlabel("Normed entropy")
        axis.set_ylabel("Density")
    else:
        axis.plot(switch_port.time, switch_port.entropies[1:], label="entropy")
        axis.set_title("Entropy level")
        axis.set_xlabel("time(second)")
        axis.set_ylabel("Normed entropy")
    plt.legend()
    plt.show()

def plot_inter_arrival_time(packet_sink, density=False):
    axis = plt.subplots()[1]
    if density:
        axis.hist(packet_sink.arrivals, 200, density=True,  label="Inter-arrival time density")
        axis.set_title("Inter-arrival time density distribution")
        axis.set_xlabel("Inter arrival time")
        axis.set_ylabel("Density")
    else:
        axis.plot(ps.time, ps.arrivals, label="Inter arrival time")
        axis.set_title("Inter-arrival time")
        axis.set_xlabel("Time")
        axis.set_ylabel("Inter-arrival time")
    plt.legend()
    plt.show()

def plot_average_waiting_time(packet_sink, density=False):
    axis = plt.subplots()[1]
    if density:
        axis.hist(ps.average_wait, 200, density=True, label="waiting time density")
        axis.set_title("Average waiting time density")
        axis.set_xlabel("Average wait")
        axis.set_ylabel("Density")
    else:
        axis.plot(ps.time, ps.average_wait, label="waiting time")
        axis.set_title("Average waiting time")
        axis.set_xlabel("Time")
        axis.set_ylabel("time/packet")
    plt.legend()
    plt.show()

def plot_port_receive_rate(switch_port, density=False):
    axis = plt.subplots()[1]
    if density:
        axis.hist(switch_port.rec_rate, 200, density=True, label="Average receive rate density")
        axis.set_title("Average port packet receive density")
        axis.set_xlabel("Average receive rate(packets/time)")
        axis.set_ylabel("Density")
    else:
        axis.plot(switch_port.time, switch_port.rec_rate, label="recieve rate")
        axis.set_title("Average port packet receive rate")
        axis.set_xlabel("Time")
        axis.set_ylabel("packets/time")
    plt.legend()
    plt.show()

def plot_buffer_size(switch_port, density=False):
    axis = plt.subplots()[1]
    if density:
        axis.hist(switch_port.buffer_size, 200, density=True, label="Buffer size density")
        axis.set_title("Port buffer size density")
        axis.set_xlabel("Packets")
        axis.set_ylabel("Density")
    else:
        axis.plot(switch_port.time, switch_port.buffer_size, label="Buffer size")
        axis.set_title("Port buffer size")
        axis.set_xlabel("Time")
        axis.set_ylabel("Packets")
    plt.legend()
    plt.show()

def plot_packet_recieved(packet_sink, comment):
    axis = plt.subplots()[1]
    for ip in packet_sink.packet_box:
        axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["packets_rec"], label=ip+comment[ip])
    axis.set_title("Packets received")
    axis.set_xlabel("Time")
    axis.set_ylabel("Packets")
    plt.legend()
    plt.show()

def plot_packet_inter_arrival_time(packet_sink, comment):
    axis = plt.subplots()[1]
    for ip in packet_sink.packet_box:
        axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["arrival_rate"], label=ip+comment[ip])
    axis.set_title("Average inter arrival time")
    axis.set_xlabel("Time")
    axis.set_ylabel("Inter-arrival time")
    plt.legend()
    plt.show()

def plot_packet_average_wait_time(packet_sink, comment):
    fig, axis = plt.subplots()
    for ip in ps.packet_box :
        axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["average_wait"], label=ip+comment[ip])
    axis.set_title("Average wait time")
    axis.set_xlabel("Time")
    axis.set_ylabel("Time/packet")
    plt.legend()
    plt.show()


if __name__ == '__main__':
    env = simpy.Environment()

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Cancel":
            break
            exit()
        elif event == "OK":
            packets_gen = []
            mean_pkt_size = int(values["-PACKETSIZE-"])
            adist1 = functools.partial(random.expovariate, 1/float(values["-ARRIVALRATE-"]))
            attadist = functools.partial(random.expovariate, 1/float(values["-ATTARRIVALRATE-"]))
            sdist = functools.partial(random.expovariate, 1.0/mean_pkt_size)
            port_rate = float(values["-PORTRATE-"])*8*mean_pkt_size
            start_ip = values["-STARTIP-"]
            switch_port = SwitchPort(env, port_rate, debug=False, qlimit=int(values["-BUFFERSIZE-"]))
            comment = {}

            num_of_att = values["-NUMATTNODES-"]
            if num_of_att == "": num_of_att = 0
            else: num_of_att = int(num_of_att)
            finish = values["-ATTACKENDTIME-"]
            if finish == "": finish = float("inf")
            else: finish = float(finish)
            attack_time = values["-ATTACKTIME-"]
            if attack_time == "": attack_time = 0
            else: attack_time = float(attack_time)
            if finish <= attack_time: raise ValueError("Attact time must be less than attack finish time")
            num_of_pg = int(values["-NUMPACKETSGEN-"])
            if num_of_pg < 2: raise ValueError("Number of packet generator must be greater than 1")
            for i in range(num_of_pg):
                if num_of_att == 0:
                    pg = PacketGenerator(env, start_ip, adist1, sdist)
                    comment[start_ip] = ""
                else:
                    pg = PacketGenerator(env, start_ip, attadist, sdist, initial_delay=attack_time, finish=finish)
                    num_of_att -= 1
                    comment[start_ip] = " ATTACKER"
                pg.out = switch_port
                packets_gen.append(pg)
                split = start_ip.split(".")
                if split[-1] == "255":
                    if split[-2] == "255":
                        if split[-3] == "255":
                            if split[-4] == "255":
                                raise ValueError("Invalid Ip address")
                            else:
                                start_ip = str(int(split[-4]) + 1) + ".0.0.0"
                        else:
                            start_ip = ".".join([split[-4], str(int(split[-3]) + 1)]) + ".0.0"
                    else:
                        start_ip = ".".join([split[-4], split[-3], str(int(split[-2]) + 1)]) + ".0"
                else:
                    start_ip = ".".join([split[-4], split[-3], split[-2], str(int(split[-1]) + 1)])
            ps = PacketSink(env, debug=False, rec_arrivals=True, entropy_window=int(values["-ENTROPYWIN-"]), entropy_time_window=int(values["-ENTROPYTIMEWIN-"]))
            switch_port.out = ps
            window.close()
            env.run(until=float(values["-RUNTIME-"]))

            print("average wait = {}".format(sum(ps.waits)/len(ps.waits)))
            print("packets sent {}".format(sum(pg.packets_sent for pg in packets_gen)))
            print("packets received: {}".format(ps.packets_rec))
            print("packets dropped: {}".format(switch_port.packets_drop))

            
            plot_entropy(switch_port)
            #plot_packet_average_wait_time(ps, comment)
            #plot_packet_inter_arrival_time(ps, comment)
            #plot_packet_recieved(ps, comment)
            #plot_buffer_size(switch_port)
            #plot_port_receive_rate(switch_port)
            #plot_average_waiting_time(ps)
            #plot_inter_arrival_time(ps)
            break

