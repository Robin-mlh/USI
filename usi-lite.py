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
    hote = input("Adresse du serveur à joindre (défaut localhost) : ")
    if not hote:
        hote = "localhost"
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
            elif "<système>" in message_recu:
                afficher(message_recu)
            elif message_recu.startswith("!:s"):
                afficher(message_recu[3:])
            else:
                afficher(f"{infos_connexion[0]}>> {message_recu}")
            if serveur and len(liste_connexions) > 1:
                envoi_message(f"!:s{infos_connexion[0]}>> {message_recu}", co_reception=connexion,
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
        msg_a_envoyer = input().rstrip()
        if msg_a_envoyer.startswith("!:s"):
            msg_a_envoyer = msg_a_envoyer[3:]
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
            afficher(f"""{msg_a_envoyer} >\n   !cls      Nettoyer l'écran\n   !fermer   Fermer la connexion""")
        elif msg_a_envoyer == "!fermer":
            if serveur:
                envoi_message("!serveur-fermeture", afficher_message=False)
            else:
                envoi_message("!client-fermeture", afficher_message=False)
            ferme_connexion(infos_connexion)
        else:
            envoi_message(msg_a_envoyer)


def envoi_message(message, co_reception=None, afficher_message=True):
    if afficher_message:
        afficher(message)
    for co in liste_connexions:
        if co != co_reception:
            co.sendall(message.encode())


def ferme_connexion(infos_connexion, connexion=None):
    global liste_connexions
    global quitter

    if not quitter:
        if not connexion or not serveur:
            quitter = True
            for co in liste_connexions:
                co.shutdown(socket.SHUT_WR)
            liste_connexions = []
            afficher("<système> Connexion fermée.")
            exit(0)
        else:
            connexion.close()
            try:
                liste_connexions.remove(connexion)
                afficher(f"<système> Le client {infos_connexion[0]} s'est déconnecté.")
                if liste_connexions:
                    envoi_message(f"<système> Le client {infos_connexion[0]} s'est déconnecté.",
                                  co_reception=connexion, afficher_message=False)
                if not liste_connexions:
                    print("\nEn attente de client...  ctrl+c pour quitter")
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
        raise SystemExit(f"Le port {port} est déjà utilisé.")
    try:
        sock_ip_locale = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ip_locale.connect(('1.1.1.1', 80))
        ip_locale = sock_ip_locale.getsockname()[0]
    except socket.error:
        try:
            ip_locale = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            ip_locale = "127.0.0.1"
    sock_ip_locale.close()
    afficher(f"En attente de client - Adresse ip locale: {ip_locale} - Port écouté: {port}\n")
    sock.listen()
    sock.settimeout(0.5)
    thread_envoi_lance = False
    print("En attente de client...  ctrl+c pour quitter")
    while not quitter:
        while not quitter:
            try:
                connexion, infos_connexion = sock.accept()
                break
            except (socket.timeout, OSError):
                pass
        if quitter:
            break
        liste_connexions.append(connexion)
        afficher(f"<système> Le client {infos_connexion[0]} c'est connecté.")
        threading.Thread(target=reception, args=[connexion, infos_connexion]).start()
        if not thread_envoi_lance:
            threading.Thread(target=thread_envoi).start()
            thread_envoi_lance = True
        envoi_message(f"<système> Le client {infos_connexion[0]} c'est connecté.",
                      co_reception=connexion, afficher_message=False)
else:
    infos_connexion = (hote, port)
    connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"Connexion à {hote}:{port}...   ctrl+c pour annuler")
    afficher_en_attente = True
    while True:
        try:
            connexion.connect((hote, port))
            break
        except (ConnectionRefusedError, TimeoutError) as e:
            if afficher_en_attente:
                afficher(f"En attente du serveur ({hote}:{port})...   ctrl+c pour quitter")
                afficher_en_attente = False
            time.sleep(0.2)
        except (socket.gaierror, OSError):
            raise SystemExit(f"L'adresse {hote} est invalide.")
        except OverflowError:
            raise SystemExit(f"Le port {port} invalide.")
    liste_ecran = []
    afficher(f"Connexion établie avec le serveur {hote}:{port}\n")
    liste_connexions.append(connexion)
    threading.Thread(target=reception, args=[connexion, (hote, port)]).start()
    thread_envoi()
