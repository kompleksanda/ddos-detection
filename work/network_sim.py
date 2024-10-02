from SimComponents import PacketGenerator, PacketSink, SwitchPort, RandomBrancher
import functools
import simpy
import random
import matplotlib.pyplot as plt
import PySimpleGUI as sg

layout = [
            [sg.Text("How many packet generators nodes"), sg.In(size=(3, 1), enable_events=True, default_text="2", key="-NUMPACKETSGEN-")],
            [sg.Text("Number of attacker nodes"), sg.In(size=(3, 1), default_text="0", enable_events=True, key="-NUMATTNODES-")],
            [sg.Text("Normal arrival rates within"), sg.In(size=(3, 1), default_text="2", enable_events=True, key="-ARRIVALRATE-")],
            [sg.Text("Time to start attack"), sg.In(size=(4, 1), default_text="500", enable_events=True, key="-ATTACKTIME-")],
            [sg.Text("Attacker arrival rates within"), sg.In(size=(3, 1), default_text="0.5", enable_events=True, key="-ATTARRIVALRATE-")],
            [sg.Text("Packet size within"), sg.In(size=(3, 1), default_text="200", enable_events=True, key="-PACKETSIZE-")],
            [sg.Text("Switch port rate"), sg.In(size=(3, 1), enable_events=True, default_text="2", key="-PORTRATE-")],
            [sg.Text("Run for"), sg.In(size=(5, 1), enable_events=True, default_text="1000", key="-RUNTIME-")],
            [sg.Text("Start IP"), sg.In(size=(15, 1), enable_events=True, default_text="10.0.0.1", key="-STARTIP-")],
            [sg.Button("OK")],
        ]

window = sg.Window("Entropy", layout, margins=(100, 50))

if __name__ == '__main__':
    env = simpy.Environment()

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
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
            switch_port = SwitchPort(env, port_rate, debug=False, qlimit=10)
            num_of_att = int(values["-NUMATTNODES-"])
            comment = {}
            for i in range(int(values["-NUMPACKETSGEN-"])):
                if num_of_att == 0:
                    pg = PacketGenerator(env, start_ip, adist1, sdist)
                    comment[start_ip] = ""
                else:
                    pg = PacketGenerator(env, start_ip, attadist, sdist, initial_delay=float(values["-ATTACKTIME-"]))
                    num_of_att -= 1
                    comment[start_ip] = " ATTACKER"
                pg.out = switch_port
                packets_gen.append(pg)
                split = start_ip.split(".")
                if split[-1] == "255":
                    if split[-2] == "255":
                        if split[-3] == "255":
                            if split[-4] == "255":
                                raise Exception("Invalid Ip address")
                            else:
                                start_ip = str(int(split[-4]) + 1) + ".0.0.0"
                        else:
                            start_ip = ".".join([split[-4], str(int(split[-3]) + 1)]) + ".0.0"
                    else:
                        start_ip = ".".join([split[-4], split[-3], str(int(split[-2]) + 1)]) + ".0"
                else:
                    start_ip = ".".join([split[-4], split[-3], split[-2], str(int(split[-1]) + 1)])
            ps = PacketSink(env, debug=True, rec_arrivals=True)
            switch_port.out = ps
            window.close()
            env.run(until=float(values["-RUNTIME-"]))
            print(len(packets_gen))
            print("average wait = {}".format(sum(ps.waits)/len(ps.waits)))
            print("average rates = {}".format(switch_port.rec_rate[-10:]))
            print("packets sent {}".format(sum(pg.packets_sent for pg in packets_gen)))
            print("packets received: {}".format(ps.packets_rec))
            print("packets dropped: {}".format(switch_port.packets_drop))
            """
            fig, axis = plt.subplots()
            axis.vlines(ps.arrivals, 0.0, 1.0,colors="g", linewidth=2.0, label='input stream')
            axis.set_title("Arrival times")
            axis.set_xlabel("time")
            axis.set_ylim([0, 2])
            axis.set_xlim([0, max(ps.arrivals)+1])
            plt.show()
            """

            #fig, axis = plt.subplots()
            #for ip in ps.packet_box :
            #    axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["average_wait"], label=ip+comment[ip])
                
            #    axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["arrival_rate"], label=ip+comment[ip])
            #    axis.plot(ps.packet_box[ip]["time"], ps.packet_box[ip]["packets_rec"], label=ip+comment[ip])
            #axis.set_title("Average waiting times")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("time/packet")
            
            #axis.set_title("Average inter arrival time")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("time(second)")

            #axis.set_title("packet received")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("packet")
            #plt.legend()
            #plt.show()

            #fig, axis = plt.subplots()
            #axis.plot(switch_port.time, switch_port.buffer_size, label="buffer_size")
            #axis.hist(switch_port.buffer_size, 200, density=True, label="buffer_size density")
            #axis.set_title("Switch port buffer size")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("packets")

            #axis.plot(switch_port.time, switch_port.rec_rate, label="recieve_rate")
            #axis.hist(switch_port.rec_rate, 200, density=True, label="receive rate density")
            #axis.set_title("Switch port packet receival rate")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("packets/second")

            #axis.plot(ps.time, ps.average_wait, label="waiting time")
            #axis.hist(ps.average_wait, 200, density=True, label="waiting time density")
            #axis.set_title("Average waiting time")
            #axis.set_xlabel("time(second)")
            #axis.set_ylabel("time/packet")
            

            #axis.plot(ps.time, ps.arrivals, label="arrivals")
            #axis.hist(ps.arrivals, 200, density=True,  label="arrivals")
            #plt.legend()

            #plt.show()
            break