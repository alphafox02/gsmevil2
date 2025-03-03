"""
About: This program shows you sender number, receiver number, sms text, sending time of cellphones around you.

Disclaimer:-
This program was made to understand how GSM network works. Not for bad hacking !
We are not responsible for any illegal activity !

About:-
Author: sheryar (ninjhacks)
Created on : 19/09/2019
Program : GsmEvil
Version : 2.0.0
"""

#!/usr/bin/env python
import eventlet
eventlet.monkey_patch()

import pyshark
from optparse import OptionParser
import os, sys
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import sqlite3
from datetime import datetime
import logging

# Global Variables
grgsm = "off"
gsm_sniffer = "off"
imsi_sniffer = "off"
sms_sniffer = "off"
lac = ""
ci = ""
imsi_live_db = {}
text = ""
sender = ""
receiver = ""
time = ""

class GsmSniffer:
    @staticmethod
    def sniffer():
        global gsm_sniffer, sms_sniffer, imsi_sniffer
        while True:
            if gsm_sniffer == "on":
                try:
                    capture = pyshark.LiveCapture(interface='lo', bpf_filter='port 4729 and not icmp and udp')
                    # Sniff for a short period to avoid blocking indefinitely
                    capture.sniff(timeout=1)
                    for packet in capture:
                        if sms_sniffer == "off" and imsi_sniffer == "off":
                            gsm_sniffer = "off"  # Stop sniffer if both are off
                        layer = packet.highest_layer
                        if layer == "GSM_SMS":
                            if sms_sniffer == "on":
                                SmsEvil().get_sms(packet)
                        elif layer == "GSM_A.CCCH":
                            if imsi_sniffer == "on":
                                ImsiEvil().get_imsi(packet)
                except Exception as e:
                    print("Sniffer error:", e)
            eventlet.sleep(1)

class ImsiEvil:
    def sql_db(self):
        self.sql_conn = sqlite3.connect('database/imsi.db')
        self.sql_conn.execute(
            'CREATE TABLE IF NOT EXISTS imsi_data(id INTEGER PRIMARY KEY, imsi TEXT, tmsi TEXT, mcc INTEGER, mnc INTEGER, lac INTEGER, ci INTEGER, date_time timestamp)'
        )

    def save_data(self):
        date_time = datetime.now().strftime("%H:%M:%S %Y-%m-%d")
        self.sql_conn.execute(
            'INSERT INTO imsi_data(imsi, tmsi, mcc, mnc, lac, ci, date_time) VALUES ( ?, ?, ?, ?, ?, ?, ?)', 
            (self.imsi, self.tmsi, self.mcc, self.mnc, lac, ci, date_time)
        )
        self.sql_conn.commit()
        self.max_id = self.sql_conn.execute('SELECT max(id) FROM imsi_data')
        self.imsi_id = self.max_id.fetchone()[0]

    def get_data(self):
        self.sql_db()
        self.cur = self.sql_conn.cursor()
        self.cur.execute('SELECT * FROM imsi_data WHERE imsi=?', (self.imsi,))
        self.data = self.cur.fetchall()

    def get_all_data(self):
        self.sql_db()
        self.cur = self.sql_conn.cursor()
        self.cur.execute('SELECT * FROM imsi_data')
        data = self.cur.fetchall()
        return data

    def update_data(self, id_, tmsi):
        self.sql_conn.execute(
            'UPDATE imsi_data SET tmsi = ?, date_time = ? WHERE id= ?',
            (tmsi, datetime.now().strftime("%H:%M:%S %Y-%m-%d"), id_)
        )
        self.sql_conn.commit()
        self.imsi_id = id_

    def filter_imsi(self):
        global imsi_live_db
        self.sql_db()
        self.get_data()
        data = self.data
        if data:
            data = self.data[0]
            if self.imsi != data[1]:
                self.save_data()
            else:
                if (self.tmsi != data[2]) and (self.tmsi != ''):
                    self.update_data(data[0], self.tmsi)
        else:
            self.save_data()
        
        if self.imsi in imsi_live_db:
            if imsi_live_db[self.imsi]['tmsi'] != self.tmsi:
                imsi_live_db[self.imsi]['tmsi'] = self.tmsi
        else:
            imsi_live_db[self.imsi] = {"id": self.imsi_id, "tmsi": self.tmsi, "mcc": self.mcc, "mnc": self.mnc}
        self.output()

    def get_imsi(self, packet):
        global ci, lac
        if packet[4].layer_name == 'gsm_a.ccch':
            gsm_a_ccch = packet[4]
            if hasattr(gsm_a_ccch, "gsm_a_bssmap_cell_ci"):
                ci = int(gsm_a_ccch.gsm_a_bssmap_cell_ci, 16)
                lac = int(gsm_a_ccch.gsm_a_lac, 16)
            elif hasattr(gsm_a_ccch, 'e212.imsi'):
                self.imsi = gsm_a_ccch.e212_imsi
                self.mcc = gsm_a_ccch.e212_mcc
                self.mnc = gsm_a_ccch.e212_mnc
                if hasattr(gsm_a_ccch, 'gsm_a_rr_tmsi_ptmsi'):
                    self.tmsi = gsm_a_ccch.gsm_a_rr_tmsi_ptmsi
                elif hasattr(gsm_a_ccch, 'gsm_a_tmsi'):
                    self.tmsi = gsm_a_ccch.gsm_a_tmsi
                else:
                    self.tmsi = ''
                self.filter_imsi()
        elif packet[6].layer_name == 'gsm_a.ccch':
            gsm_a_ccch = packet[6]
            if hasattr(gsm_a_ccch, "gsm_a_bssmap_cell_ci"):
                ci = int(gsm_a_ccch.gsm_a_bssmap_cell_ci, 16)
                lac = int(gsm_a_ccch.gsm_a_lac, 16)
    
    def output(self):
        data = {
            0: str(imsi_live_db[self.imsi]["id"]),
            1: self.imsi,
            2: imsi_live_db[self.imsi]["tmsi"],
            3: self.mcc,
            4: self.mnc,
            5: lac,
            6: ci,
            7: datetime.now().strftime("%H:%M:%S %Y-%m-%d")
        }
        print(data)
        socketio.emit('imsi', data)
        print("\033[0;37;48m {:3s}\033[0;31;48m; \033[0;37;48m {:16s} \033[0;31;48m; \033[0;37;48m {:12s}\033[0;31;48m; \033[0;37;48m\033[0;37;48m  {:5s} \033[0;31;48m;\033[0;37;48m   {:4s}\033[0;31;48m; \033[0;37;48m {:5}  \033[0;31;48m; \033[0;37;48m {:6}   \033[0;31;48m;".format(
            str(imsi_live_db[self.imsi]["id"]), self.imsi, imsi_live_db[self.imsi]["tmsi"], self.mcc, self.mnc, lac, ci))
        print("\033[0;31;48m................................................................................")

class SmsEvil:
    def sql_db(self):
        self.sql_conn = sqlite3.connect('database/sms.db')
        self.sql_conn.execute(
            'CREATE TABLE IF NOT EXISTS sms_data(id INTEGER PRIMARY KEY, text TEXT, sender TEXT, receiver TEXT, date_time timestamp)'
        )

    def get_all_data(self):
        self.sql_db()
        self.cur = self.sql_conn.cursor()
        self.cur.execute('SELECT * FROM sms_data')
        data = self.cur.fetchall()
        return data

    def save_data(self):
        self.sql_conn.execute(
            'INSERT INTO sms_data(text, sender, receiver, date_time) VALUES ( ?, ?, ?, ?)',
            (self.text, self.sender, self.receiver, self.time + " " + self.date)
        )
        self.sql_conn.commit()
        self.max_id = self.sql_conn.execute('SELECT max(id) FROM sms_data')
        self.sms_id = self.max_id.fetchone()[0]

    def output(self):
        self.sql_db() 
        self.save_data()
        data = {
            0: self.sms_id,
            1: self.text,
            2: self.sender,
            3: self.receiver,
            4: datetime.now().strftime("%H:%M:%S %Y-%m-%d")
        }
        print(data)
        socketio.emit('sms', data)

    def get_sms(self, packet):
        gsm_sms = packet.gsm_sms
        if hasattr(gsm_sms, 'sms_text'):
            self.time = packet.gsm_sms.scts_hour + ":" + packet.gsm_sms.scts_minutes + ":" + packet.gsm_sms.scts_seconds
            self.date = packet.gsm_sms.scts_day + "/" + packet.gsm_sms.scts_month + "/" + packet.gsm_sms.scts_year
            self.sender = packet.gsm_sms.tp_oa
            self.receiver = packet[6].gsm_a_dtap_cld_party_bcd_num
            self.text = packet.gsm_sms.sms_text
            self.output()

def header():
    os.system('clear')
    title = '''
   ▄██████▄     ▄████████   ▄▄▄▄███▄▄▄▄      ▄████████  ▄█    █▄   ▄█   ▄█      
  ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███ ███    ███ ███  ███      
  ███    █▀    ███    █▀  ███   ███   ███   ███    █▀  ███    ███ ███▌ ███      
 ▄███          ███        ███   ███   ███  ▄███▄▄▄     ███    ███ ███▌ ███      
▀▀███ ████▄  ▀███████████ ███   ███   ███ ▀▀███▀▀▀     ███    ███ ███▌ ███      
  ███    ███          ███ ███   ███   ███   ███    █▄  ███    ███ ███  ███      
  ███    ███    ▄█    ███ ███   ███   ███   ███    ███ ███    ███ ███  ███▌    ▄
  ████████▀   ▄████████▀   ▀█   ███   █▀    ██████████  ▀██████▀  █▀   █████▄▄██
                                                                       ▀        
                          ☠️  Ɠ丂爪 丂几丨千千乇尺  ☠️
--------------------------------------------------------------------------------

About:-
Author: sheryar (ninjhacks)
Version : 2.1.0

Disclaimer:-
This program was made to understand how GSM network works.
Not for bad hacking !
We are not responsible for any illegal activity !
--------------------------------------------------------------------------------
    '''
    print("\033[0;31;48m" + title)

if __name__ == "__main__":
    parser = OptionParser(usage="%prog: [options]")
    parser.add_option("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
    parser.add_option("-p", "--port", dest="port", default="80", type="int", help="Port (default : 80)")
    parser.add_option("--host", dest="host", default="localhost", help="Host (default : localhost)")
    (options, args) = parser.parse_args()

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.config['COMPRESSOR_STATIC_PREFIX'] = 'static'
    app.static_folder = 'static'
    app.logger.disabled = True
    log = logging.getLogger('werkzeug')
    log.disabled = True
    socketio = SocketIO(app, async_mode='eventlet')

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/sms/')
    def sms():
        return render_template('sms.html')

    @app.route('/imsi/')
    def imsi():
        return render_template('imsi.html')

    @socketio.on('sms_sniffer')
    def handel_sms_event(json):
        global gsm_sniffer, sms_sniffer
        if json == "on" and sms_sniffer != "on":
            sms_sniffer = "on"
            print("sms sniffer started")
            if gsm_sniffer == 'off':
                gsm_sniffer = "on"
        elif json == "off" and sms_sniffer != "off":
            sms_sniffer = "off"
            print("sms sniffer stopped")
        socketio.emit('sniffers', {'imsi_sniffer': imsi_sniffer, 'sms_sniffer': sms_sniffer})
        return gsm_sniffer, sms_sniffer

    @socketio.on('imsi_sniffer')
    def handel_imsi_event(json):
        global gsm_sniffer, imsi_sniffer
        if json == "on" and imsi_sniffer != "on":
            imsi_sniffer = "on"
            print('imsi sniffer started')
            if gsm_sniffer == "off":
                gsm_sniffer = "on"
        elif json == "off" and imsi_sniffer != "off":
            imsi_sniffer = "off"
            print('imsi sniffer stopped')
        socketio.emit('sniffers', {'imsi_sniffer': imsi_sniffer, 'sms_sniffer': sms_sniffer})
        return gsm_sniffer, imsi_sniffer

    @socketio.on('sms_data')
    def handel_sms_data_event(json):
        socketio.emit('sniffers', {'imsi_sniffer': imsi_sniffer, 'sms_sniffer': sms_sniffer})
        smsEvil = SmsEvil()
        sms_data = smsEvil.get_all_data()
        socketio.emit('sms_data', sms_data)

    @socketio.on('imsi_data')
    def handel_imsi_data_event(json):
        socketio.emit('sniffers', {'imsi_sniffer': imsi_sniffer, 'sms_sniffer': sms_sniffer})
        imsiEvil = ImsiEvil()
        imsi_data = imsiEvil.get_all_data()
        socketio.emit('imsi_data', imsi_data)

    # Start the sniffer as a background task
    socketio.start_background_task(GsmSniffer.sniffer)

    header()  # Display header info

    # Run the SocketIO server (this will block the main thread)
    socketio.run(app, host=options.host, port=options.port)
