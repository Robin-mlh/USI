#!/usr/bin/python3

""" Version réduite de USI: Communications simples. """

import os
import time
import threading
import socket

LEN_BUFFER_TCP = 16384
liste_ecran = []
liste_connexions = []
quitter = False
if os.name == "nt":
    cls = "cls"
else:
    cls = "clear"

if input("Mode client ou serveur ? [C/s] ") in ["s", "S", "serveur"]:
    serveur = True
else:
    serveur = False
    hote = input("Adresse du serveur (défaut 127.0.0.1) : ")
    if not hote:
        hote = "127.0.0.1"
try:
    port = input("Port (défaut 12800) : ")
    if not port:
        port = 12800
    else:
        port = int(port)
except Exception:
    raise SystemExit("Erreur: port invalide.")


def reception(connexion, infos_connexion):
    while connexion in liste_connexions:
        try:
            message_recu = connexion.recv(LEN_BUFFER_TCP)
            if not message_recu:
                ferme_connexion(infos_connexion, connexion)
                break
            message_recu = message_recu.decode()
            if message_recu == "!client-fermeture" and serveur:
                ferme_connexion(infos_connexion, connexion)
            elif message_recu == "!serveur-fermeture" and not serveur:
                ferme_connexion(infos_connexion, connexion)
            elif message_recu.startswith("!!"):
                afficher(message_recu[2:])
            else:
                afficher(f"{infos_connexion[0]}>> {message_recu}")
                if serveur:
                    envoi_message(message_recu, co_reception=connexion,
                                  afficher_message=False)
        except (ConnectionResetError, ValueError, ConnectionAbortedError, OSError):
            ferme_connexion(infos_connexion, connexion)
            break


def thread_envoi():
    global liste_ecran
    if serveur:
        print()
    print("Appuyez sur ENTRÉE pour envoyer votre message."
          "\nEn attente de message entrant...")
    while not quitter:
        msg_a_envoyer = input()
        if msg_a_envoyer == "":
            afficher()
        elif msg_a_envoyer == "!cls":
            liste_ecran = []
            if serveur:
                afficher(f"En attente de client - Adresse ip locale: {ip_locale} "
                         f"- Port écouté: {port}\n")
            else:
                afficher(f"Connexion établie avec le serveur: {hote}:{port}\n")
        elif msg_a_envoyer in ["!help", "!aide", "!aled"]:
            afficher(f"""{msg_a_envoyer} >\n   !cls      Nettoyer l'écran
   !fermer   Fermer la connexion""")
        else:
            envoi_message(msg_a_envoyer)
        if msg_a_envoyer in ["!fermer", "!ferme"]:
            if serveur:
                envoi_message("!serveur-fermeture", afficher_message=False)
            else:
                envoi_message("!client-fermeture", afficher_message=False)
            ferme_connexion(infos_connexion)


def envoi_message(message, co_reception=None,
                  afficher_message=True):
    if afficher_message:
        afficher(message)
    for co in liste_connexions:
        if co != co_reception:
            co.sendall(message.encode())


def ferme_connexion(infos_connexion, connexion=None):
    global liste_connexions
    global quitter

    if not connexion or not serveur:
        if not quitter:
            quitter = True
            for co in liste_connexions:
                co.shutdown(socket.SHUT_WR)
            liste_connexions = []
        afficher("<Système> Connexion fermée.")
        exit(0)
    elif not quitter:
        connexion.close()
        try:
            liste_connexions.remove(connexion)
            afficher(f"<Système> Le client {infos_connexion[0]} s'est déconnecté.")
            if liste_connexions:
                envoi_message(f"!!<Système> Le client {infos_connexion[0]} s'est déconnecté.",
                              co_reception=connexion, afficher_message=False)
        except Exception:
            pass


def afficher(nouvel_element=None):
    global liste_ecran
    if nouvel_element is not None:
        liste_ecran.append(nouvel_element)
    os.system(cls)
    for element in liste_ecran:
        print(element)


if serveur:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", port))
    except OSError:
        raise SystemExit("Erreur: ce port est déjà utilisé.")
    try:
        sock_ip_locale = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ip_locale.connect(('10.255.255.255', 1))
        ip_locale = sock.getsockname()[0]
    except Exception:
        ip_locale = "127.0.0.1"
    sock_ip_locale.close()
    afficher(f"En attente de client - Adresse ip locale: {ip_locale}"
             f" - Port écouté: {port}\n")
    sock.listen()
    sock.settimeout(0.5)
    thread_envoi_lance = False
    message_attente = True
    while not quitter:
        while not quitter:
            if len(liste_connexions) == 0 and message_attente:
                print("\nEn attente de client...  Ctrl+C pour quitter")
                message_attente = False
            try:
                connexion, infos_connexion = sock.accept()
                message_attente = True
                break
            except (socket.timeout, OSError):
                pass
        if quitter:
            break
        liste_connexions.append(connexion)
        afficher(f"<Système> Le client {infos_connexion[0]} c'est connecté.")
        threading.Thread(target=reception, args=[connexion, infos_connexion]).start()
        if not thread_envoi_lance:
            threading.Thread(target=thread_envoi).start()
            thread_envoi_lance = True
        envoi_message(f"!!<Système> Le client {infos_connexion[0]} c'est connecté.",
                      co_reception=connexion, afficher_message=False)
else:
    infos_connexion = (hote, port)
    connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    afficher_en_attente = True
    while True:
        try:
            connexion.connect((hote, port))
            break
        except (ConnectionRefusedError, TimeoutError) as e:
            if afficher_en_attente:
                print(f"En attente du serveur ({hote}:{port})...   (Ctrl+C pour annuler)")
                afficher_en_attente = False
            time.sleep(0.2)
        except (socket.gaierror, OSError):
            raise SystemExit("Erreur: adresse invalide.")
        except OverflowError:
            raise SystemExit("Erreur: port invalide.")
    afficher(f"Connexion établie avec le serveur {hote}:{port}\n")
    liste_connexions.append(connexion)
    threading.Thread(target=reception, args=[connexion, (hote, port)]).start()
    thread_envoi()
