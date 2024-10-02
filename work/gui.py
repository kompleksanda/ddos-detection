import PySimpleGUI as sg

layout = [
            [sg.Text("How many packet generators"), sg.In(size=(3, 1), enable_events=True, key="-NUMPACKETSGEN-")],
            [sg.Text("Arrival rates within"), sg.In(size=(3, 1), enable_events=True, key="-ARRIVALRATE-")],
            [sg.Text("Packet size within"), sg.In(size=(3, 1), enable_events=True, key="-PACKETSIZE-")],
            [sg.Text("Port rate"), sg.In(size=(3, 1), enable_events=True, key="-PORTRATE-")],
            [sg.Text("Start IP"), sg.In(size=(15, 1), enable_events=True, key="-STARTIP-")],
            [sg.Button("OK")],
        ]

window = sg.Window("Entropy", layout, margins=(100, 50))

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break
    elif event == "OK":
        print(values)

window.close()