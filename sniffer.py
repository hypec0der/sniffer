
from scapy.all import *
import argparse
from threading import Thread, Event
from queue import Queue
import time
import os


args = None
qprinter = Queue ()


class Printer ( Thread ) :

    args = None
    qprinter = None

    def __init__ ( self ) :

        super ().__init__ ()

        self.args = args
        self.qprinter = qprinter

        self.stop_printer = Event ()
        

    def join ( self, timeout = None ):

        self.stop_printer.set ()

        super () .join( timeout )

    
    def run ( self ):
        
        while not self.stop_printer.isSet ():

            if not self.qprinter.empty ():

                packet = self.qprinter.get ()

                if self.args.hexdump :
                    print ( hexdump ( packet ))

                elif self.args.raw :
                    print ( raw ( packet ))

                elif self.args.list :
                    print ( ls ( packet )) 

                elif self.args.show2:
                    print ( packet.show2() )

                elif self.args.summary:
                    print ( packet.summary() )

                elif self.args.command:
                    print ( packet.command() )

                elif self.args.sprintf:
                    print ( packet.sprintf( self.args.sprintf ) )
                
                elif self.args.pdfdump:
                    print ( packet.pdfdump() )
                
                elif self.args.psdump:
                    print ( packet.psdump() )

                else:
                    print ( packet.show() )



class Sniffer ( Thread ):


    args = None

    def __init__ ( self ) :

        super (). __init__ ()

        self.args = args

        self.daemon = True
        self.socket = None

        self.stop_sniffer = Event () #stop sniffer event 



    def run ( self ) :


        self.socket = conf.L2listen (

            type = ETH_P_ALL,
            iface = self.args.interface,
            filter = self.args.filters

        )  #create socket

        try:

            self.result = sniff (

                count = self.args.count,
                timeout = self.args.timeout,
                offline = self.args.offline,
                store = self.args.store,
                opened_socket = self.socket,
                prn = self.do_with_packet ,
                stop_filter = self.should_stop_sniffer   #stop if stop sniffer event is ON

            ) #start sniffing

        except Exception as error :
            print ( error )



    def join ( self, timeout = None ) :

        self.stop_sniffer.set ()  #set stop sniffer ON

        super().join ( timeout )  #join finally this thread



    def should_stop_sniffer ( self, packet ):
        self.stop_sniffer.isSet ()  #check if stop sniffer event is ON


    def do_with_packet ( self, packet ) : 
        qprinter.put ( packet )  #insert packet in queue




def main () :

    global args

    parser =  argparse.ArgumentParser ()

    parser.add_argument ( '-i', dest = 'interface', default = 'wlan0', required = False, type = str, action = 'append', help = 'Interface to bind socket' )
    parser.add_argument ( '-n', dest = 'count', default = 0, type = int, required = False, help = 'Number of packets to capture. 0 means infinity.' )
    parser.add_argument ( '-s', dest = 'store', default = 0, choices = (False,True), nargs = '?', type = bool, const = False, required = False, help = 'Wether to store sniffed packets or discard them.' )
    parser.add_argument ( '-f', dest = 'filters', type = str, required = False, default = None, help = 'Python function applied to each packet to determine.' )
    parser.add_argument ( '-m', dest = 'save', type = str, required = False, default = None, help = 'write packets captured to pcap file' )
    parser.add_argument ( '-o', dest = 'offline', type = str, required = False, default = None, help = 'Pcap file to read packets from, instead of sniffing them.' )
    parser.add_argument ( '-t', dest = 'timeout', type = int, required = False, default = None, help = 'Stop sniffing after a given time')

    subparser = parser.add_subparsers ( dest = 'More' )

    printing = subparser.add_parser ( 'Printer' )
    printing.add_argument ( '-hexdump', dest = 'hexdump', action = 'store_true', help = 'Print hexdump packet' )
    printing.add_argument ( '-raw', dest = 'raw', action = 'store_true', help = 'Assemble the packet' )
    printing.add_argument ( '-list', dest = 'list', action = 'store_true', help = 'Have a list of a fields' )
    printing.add_argument ( '-view', dest = 'show', action = 'store_true', help = 'For a developed view of the packet' )
    printing.add_argument ( '-view2', dest = 'show2', action = 'store_true', help = 'Same as show but on the assembled packet (checksum is calculated, for instance)' )
    printing.add_argument ( '-summary', dest = 'summary', action = 'store_true', help = 'For a one-line summary' )
    printing.add_argument ( '-command', dest = 'command', action = 'store_true', help = 'Return a command that can generate the packet' )
    printing.add_argument ( '-sprintf', dest = 'sprintf', type = str, default = None, help = 'Fills a format string with fields values of the packet' )
    printing.add_argument ( '-pdfdump', dest = 'pdfdump', action = 'store_true', help = 'Draws a PDF with explained dissection' )
    printing.add_argument ( '-psdump', dest = 'psdump', action = 'store_true', help = 'Draws a PostScript diagram with explained dissection' )


    information = subparser.add_parser ( 'Info' )
    information.add_argument ( '-iface', dest = 'show', action = 'store_true' )
    information.add_argument ( '-route', dest = 'route', action = 'store_true' )
    information.add_argument ( '-l3ocket', dest = 'L3socket', action = 'store_true' )


    args = parser.parse_args ()
    printer = Printer ()


    if args.More:

        if 'Printer' in args.More:
            printer.start ()
        
    try:

        if os.getuid() is 0:
            
            sniffer = Sniffer ()

            print ( 'Start sniffing on %s ... ' %args.interface )

            sniffer.start ()

            try:

                while True:
                    time.sleep (100)

            except KeyboardInterrupt :

                sniffer.join(2.0)

                if printer.is_alive():
                    printer.join (2.0)

                if sniffer.isAlive():
                    sniffer.socket.close()


            if args.save and args.store:
                wrpcap ( args.save, sniffer.result )


        else:
            raise PermissionError ( 'Permission denied!' )

    except PermissionError as error:
        print ( error )




if __name__ == '__main__':
    main ()
