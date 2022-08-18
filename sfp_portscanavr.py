# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_portscanavr
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Alberto Varona Román <albertovaronaroman@gmail.com>
#
# Created:     18/08/2022
# Copyright:   (c) Alberto Varona Román 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess

class sfp_portscanavr(SpiderFootPlugin):

    meta = {
        'name': "Port Scan Avr",
        'summary': "Check if the usual ports from a domain are opened",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            command = 'nc -zv -w1 '+eventData+' 21 23 25 53 80 110 443 465 587 993 995 8000 8080'
            data = subprocess.run(command, shell=True, capture_output=True, text=True)
            salida = data.stderr
            formateado = salida.splitlines(False)
            formateado.pop(0)
            resultado = formateado
            indice = len(formateado)-1
            while indice>=0:
                if formateado[indice].find('open') == -1:
                    resultado.pop(indice)
                indice = indice -1
            array_puertos = []
            for linea in resultado:
                indice = len(linea) - 1
                while linea[indice]!=']':
                    indice = indice -1
                linea = linea[(indice+1):]
                linea2 = linea.split(' ')
                linea2.pop(3)
                linea2.pop(2)
                linea2.pop(0)
                if linea2:
                    array_puertos.append(linea2)
               
            

            if not array_puertos:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        for puertoAbierto in array_puertos:
            evt = SpiderFootEvent("TCP_PORT_OPEN", str(puertoAbierto), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_portscanavr class