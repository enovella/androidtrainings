# -*- coding: utf-8 -*-

import frida, sys, re
import codecs, time

APP_NAME = "sg.vantagepoint.uncrackable3"
PID = int(sys.argv[1])

def sbyte2ubyte(byte):
    return (byte % 256)

def print_result(message):
    print ("[!] Received: [%s]" %(message))

def on_message(message, data):
    if 'payload' in message:
        data = message['payload']
        if type(data) is str:
            print_result(data)
        elif type(data) is list:
            a = data[0]
            if type(a) is int:
                print_result("".join([("%02X" % (sbyte2ubyte(a))) for a in data]))
            else:
                print_result(data)
        else:
            print_result(data)
    else:
        if message['type'] == 'error':
            print (message['stack'])
        else:
            print_result(message)

with codecs.open("hooks.js", 'r', encoding='utf8') as f:
    jscode  = f.read()
    device  = frida.get_usb_device(timeout=5)
    session = device.attach(PID)
    script  = session.create_script(jscode)
    #device.resume(APP_NAME)
    script.on('message', on_message)
    print ("[*] Intercepting ...")
    script.load()
    sys.stdin.read()

