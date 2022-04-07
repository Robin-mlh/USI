#!/usr/bin/python3

""" Communications simples et chiffrées. """

import sys
import os
import time
import threading
import socket
import binascii
import json
import argparse
from base64 import b64decode, b64encode
from urllib.error import URLError
from urllib.request import urlopen

import tqdm
from plyer import notification
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome import Random

LEN_BUFFER_TCP = 16384  # Taille du tampon socket en bits.
CLE_RSA = 2048  # Taille de la clé RSA en bits.
CLE_SESSION = 16  # Taille de la clé de session symétrique AES en octets.

liste_ecran = []  # Liste des éléments à afficher.
liste_cle_session = []  # Liste des clés de session.
liste_connexions = []  # Liste des objets de connexions.
quitter = False
if os.name == "nt":  # Pour Windows
    cls = "cls"
else:  # Pour linux
    cls = "clear"

# Définition des arguments de la commande.
argumentParser = argparse.ArgumentParser(description="Communications simples et chiffrées."
                                                     "\nUne fois connecté, utilisez la commande '!aide' "
                                                     "pour afficher les commandes disponibles.",
                                         usage="USI.py [-h] {-s | -c [-i HOTE]} [-p PORT] [-nd]",
                                         formatter_class=argparse.RawTextHelpFormatter, add_help=False)
argumentParser._optionals.title = 'Options'
group = argumentParser.add_mutually_exclusive_group(required=True)
group.add_argument('-s', "--serveur", action='store_true',
                   help="Utiliser le mode serveur pour attendre des clients")
group.add_argument('-c', "--client", action='store_true',
                   help="Utiliser le mode client pour se connecter à un serveur")
argumentParser.add_argument("-i", "--hote", required=False, metavar="HOTE", help="Spéficier le serveur à contacter. "
                            "Uniquement en mode client\nIl peut par exemple sagir d'une IP. (défaut: localhost)")
argumentParser.add_argument("-p", "--port", type=int, required=False, default=12800,
                            help="Spécifier le port à utiliser (defaut: 12800)", metavar="PORT")
argumentParser.add_argument("-n", "--notifications", help="Désactiver les notifications", action="store_true")
argumentParser.add_argument("-d", "--dev", help="Mode développeur", action="store_true")
argumentParser.add_argument("-v", "--version", action='version', version="USI 2.0",
                            help="Afficher la version")
argumentParser.add_argument("-h", "--help", action="help", help="Afficher ce message d'aide")
if len(sys.argv) == 1:  # Affiche l'aide si USI est lancé sans arguments.
    argumentParser.print_help(sys.stderr)
    sys.exit(1)
arguments = argumentParser.parse_args()
if arguments.hote is None:
    hote = "localhost"  # Hôte par défaut.
else:
    if arguments.serveur:  # Impossinle de spécifier l'hôte en étant le serveur.
        argumentParser.error("-i/--hote n'est pas spécifiable en mode serveur (avec -s/--serveur).")
    hote = arguments.hote


def reception(connexion, infos_connexion, cle):
    """ Attend la réception d'un message en boucle. """

    while connexion in liste_connexions:
        try:
            message_recu_brut = connexion.recv(LEN_BUFFER_TCP)  # Attend la reception d'un message.
            if not message_recu_brut:  # Connexion désactivée.
                ferme_connexion(infos_connexion, connexion)
                break
            # Déchiffrement du message.
            donnees = [b64decode(message_recu_brut[:20]),
                       b64decode(message_recu_brut[20:44]),
                       b64decode(message_recu_brut[44:])]
            objet_dechiffrement = AES.new(cle, AES.MODE_OCB, nonce=donnees[0])
            message_recu = objet_dechiffrement.decrypt_and_verify(donnees[2], donnees[1]).decode()
            if message_recu == "!client-fermeture" and arguments.serveur:  # Un client signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion)
            elif message_recu == "!serveur-fermeture" and not arguments.serveur:  # Le serveur signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion)
            elif message_recu.startswith("!!"):
                afficher(message_recu[2:])
            elif message_recu.startswith("!:f"):  # Reception d'un fichier.
                fichier, taille_fichier = message_recu[3:].split("|")
                taille_fichier = int(taille_fichier)
                afficher(f"{infos_connexion[0]}>> [Fichier {fichier} - {taille_fichier}o]")
                barre_progression = tqdm.tqdm(range(taille_fichier), f"Réception fichier",
                                              unit="o", unit_scale=True)
                with open(fichier, "wb") as f:
                    while True:
                        bytes_recu = connexion.recv(LEN_BUFFER_TCP)
                        if b"|!f|" in bytes_recu:
                            bytes_recu = bytes_recu.split(b"|!f|")[0]
                            f.write(bytes_recu)
                            barre_progression.update(len(bytes_recu))
                            barre_progression.close()
                            break
                        f.write(bytes_recu)
                        barre_progression.update(len(bytes_recu))
                if arguments.serveur and len(liste_connexions) > 1:
                    serveur_fichier(fichier, co_reception=connexion,
                                    afficher_message=False)
            else:
                if message_recu.startswith(">>"):  # Système de citation.
                    message_temp = message_recu.split(">>")
                    citation = f"               \>{message_temp[1]}"
                    message_temp = ">>".join(message_temp[2:])
                    afficher(f"{infos_connexion[0]}>> {message_temp}\n{citation}")
                elif not arguments.dev:
                    afficher(f"{infos_connexion[0]}>> {message_recu}")
                if arguments.serveur:
                    # Si serveur: relai aux autres clients du message (rechiffré par le serveur).
                    envoi_message(message_recu, co_reception=connexion,
                                  afficher_message=False)
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {infos_connexion[0]} >> {message_recu} ({message_recu_brut.decode()})")
        except (ConnectionResetError, ValueError, ConnectionAbortedError, OSError):
            ferme_connexion(infos_connexion, connexion)
            break


def thread_envoi():
    """ Demande le message à envoyer en boucle. """

    global liste_ecran

    if arguments.serveur:
        print()
    print("Appuyez sur ENTRÉE pour envoyer votre message.\nEn attente de message entrant...")
    while not quitter:
        msg_a_envoyer = input()  # Demande le message à envoyer (ou la commande à executer).
        if msg_a_envoyer == "":  # Message vide: met à jour l'écran sans nouveau message.
            afficher(notification=False)
        elif msg_a_envoyer == "!cls":  # Nettoyage de l'écran.
            liste_ecran = []
            if arguments.serveur:
                afficher(f"Adresse ip locale: {ip_locale}  Adresse ip publique: {ip_publique}  Port écouté: "
                         f"{arguments.port}\n", notification=False)
            else:
                afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}\n"
                         f"Empreinte de vérification: {empreinte_verif}\n", notification=False)
        elif msg_a_envoyer == "!fichier":  # Envoi d'un fichier.
            fichier = input("Fichier à envoyer: ")
            if os.path.isfile(fichier):  # Vérification de l'éxistence du fichier.
                serveur_fichier(fichier)  # Envoi du fichier.
            else:
                print("<Système> Erreur: Le fichier n'éxiste pas.")
        elif msg_a_envoyer in ["!help", "!aide", "!aled"]:  # Message d'aide des commandes.
            afficher(f"""{msg_a_envoyer} >\n   Pour citer un message: '>>citation>>message'
   !cls              Nettoyer l'écran
   !fermer           Fermer la connexion
   !fichier          Envoyer un fichier""", notification=False)
        elif msg_a_envoyer in ["!fermer", "!ferme"]:  # Déconnexion, fermeture.
            if arguments.serveur:  # Signalement de la déconnexion.
                envoi_message("!serveur-fermeture", afficher_message=False)
            else:
                envoi_message("!client-fermeture", afficher_message=False)
            ferme_connexion(infos_connexion)
        else:  # Message normal.
            envoi_message(msg_a_envoyer, afficher_message=False)  # Chiffrement et envoi du message.
            if msg_a_envoyer.startswith(">>"):  # Système de citation.
                msg_a_envoyer = msg_a_envoyer.split(">>")
                citation = f"   \>{msg_a_envoyer[1]}"
                msg_a_envoyer = ">>".join(msg_a_envoyer[2:])
                afficher(f"{msg_a_envoyer}\n{citation}")
            elif not arguments.dev:
                afficher(msg_a_envoyer, notification=False)


def envoi_message(message, co_reception=None, co_unique=None,
                  afficher_message=True):
    """ Envoi d'un message chiffré au(x) client(s). """

    if afficher_message and not arguments.dev:
        afficher(message, notification=False)
    for co, cle in zip(liste_connexions, liste_cle_session):
        if co != co_reception or (co_unique is not None and co_unique == co):
            # Chiffrement du message
            objet_chiffrement = AES.new(cle, AES.MODE_OCB)
            texte_chiffre, tag = objet_chiffrement.encrypt_and_digest(message.encode())
            message_chiffre = (f"{b64encode(objet_chiffrement.nonce).decode()}"
                               f"{b64encode(tag).decode()}"
                               f"{b64encode(texte_chiffre).decode()}")
            co.sendall(message_chiffre.encode())  # Envoi du message chiffré.
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {message} ({message_chiffre}) >> {co.getsockname()}", notification=False)


def serveur_fichier(fichier, co_reception=None,
                    afficher_message=True):
    """ Envoi d'un fichier (non chiffré). """

    taille_fichier = os.path.getsize(fichier)
    with open(fichier, "rb") as f:
        for co in liste_connexions:
            if co != co_reception:
                envoi_message(f"!:f{os.path.basename(fichier)}|{taille_fichier}",
                              co_unique=co, afficher_message=False)
                barre_progression = tqdm.tqdm(range(taille_fichier), "Envoi fichier",
                                              unit="o", unit_scale=True)
                while True:
                    bytes_lu = f.read(LEN_BUFFER_TCP)
                    if not bytes_lu:
                        co.sendall(b"|!f|")
                        break
                    co.sendall(bytes_lu)
                    barre_progression.update(len(bytes_lu))
                barre_progression.close()
    if afficher_message:
        afficher(f"[Fichier {fichier} - {taille_fichier}o]", notification=False)


def ferme_connexion(infos_connexion, connexion=None):
    """ Ferme la connexion. """

    global liste_connexions
    global liste_cle_session
    global quitter

    if not connexion or not arguments.serveur:
        # Déconnexion totale et fermeture du programme.
        if not quitter:
            quitter = True
            for co in liste_connexions:  # Fermeture de chaque connexion.
                co.shutdown(socket.SHUT_WR)
            liste_connexions = []
            liste_cle_session = []
            afficher("<Système> Connexion fermée.")
            exit(0)
    elif not quitter:  # déconnexion d'un seul client.
        connexion.close()
        try:
            del liste_cle_session[liste_connexions.index(connexion)]
            liste_connexions.remove(connexion)
            afficher(f"<Système> Le client {infos_connexion[0]} s'est déconnecté.")
            if liste_connexions:  # Relai aux autres clients du message de déconnexion.
                envoi_message(f"!!<Système> Le client {infos_connexion[0]} s'est déconnecté.",
                              co_reception=connexion, afficher_message=False)
        except Exception:
            pass


def afficher(nouvel_element=None, notification=True):
    """ Afficher un élément à l'écran.

        nouvel_element : Nouvel élément à afficher.
                         Si None, rafraîchit juste l'écran."""

    global liste_ecran

    if nouvel_element is not None:  # Ajout du nouvel élément à la liste affichée.
        liste_ecran.append(nouvel_element)
        if notification:
            envoi_notification(nouvel_element)
    os.system(cls)  # Nettoyage de l'écran.
    for element in liste_ecran:  # Affiche chaque élément.
        print(element)


def envoi_notification(contenu):
    """ Déclenche une notification système. """

    if not arguments.notifications:
        try:
            if arguments.serveur:
                notification.notify("USI serveur", contenu)
            else:
                notification.notify("USI client", contenu)
        except Exception:
            # Impossible d'envoyer une notification.
            pass


# Mise en place de la connexion.
if arguments.serveur:  # Serveur.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", arguments.port))
    except OSError:
        raise SystemExit("Erreur: ce port est déjà utilisé.")
    try:  # Obtention de l'ip publique.
        ip_publique = json.loads(urlopen("http://httpbin.org/ip").read())["origin"]
    except URLError:  # Adresse ip publique non disponible, vérifier la connexion.
        ip_publique = ""
    try:  # Obtention de l'ip locale.
        sock_ip_locale = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ip_locale.connect(('10.255.255.255', 1))
        ip_locale = sock.getsockname()[0]
    except Exception:
        ip_locale = "127.0.0.1"
    sock_ip_locale.close()
    afficher(f"Adresse ip locale: {ip_locale}  Adresse ip publique: {ip_publique}  Port écouté: {arguments.port}\n",
             notification=False)
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
                connexion, infos_connexion = sock.accept()  # Attend la connexion d'un client.
                message_attente = True
                break
            except (socket.timeout, OSError):
                pass
        if quitter:
            break
        cle_privee = RSA.generate(CLE_RSA)  # Génération de la clé privée RSA.
        cle_publique = cle_privee.public_key()  # Obtention de la clé publique avec la clé privée.
        connexion.sendall(b64encode(cle_publique.export_key("DER")))  # Envoi de la clé publique au client.
        recu = connexion.recv(LEN_BUFFER_TCP)
        cle_publique_client = RSA.import_key(b64decode(recu[:392]))  # Clé publique du client.
        cle_session = PKCS1_OAEP.new(cle_privee).decrypt(b64decode(recu[736:]))  # Clé de session.
        if arguments.dev:  # Mode développeur.
            afficher("[dev] Échange sécurisé de la clé de session en cours..."
                     f"\n[dev] Clé publique: {cle_publique.export_key('PEM')}"
                     f"\n[dev] Clé publique du client: {cle_publique_client.export_key('PEM')}"
                     f"\n[dev] Empreinte SHA256 de la clé de session: {SHA256.new(cle_session).hexdigest()}")
        try:  # Vérification de la signature du client avec sa clé publique.
            pss.new(cle_publique_client).verify(SHA256.new(cle_session), b64decode(recu[392:736]))
        except (ValueError, TypeError):  # Echec de la vérification de l'authenticité de la signature.
            afficher("<Système> Échange de clé avorté: la signature de la clé de session n'est pas authentique.\n"
                     "L'identité du client est peut être usurpée.")
            ferme_connexion(infos_connexion, connexion)
            continue
        empreinte_verif = SHA256.new(cle_publique_client.export_key("DER") + cle_publique.export_key("DER")).hexdigest()
        liste_connexions.append(connexion)  # Ajout de la connexion à la liste des connexions actives.
        liste_cle_session.append(cle_session)  # Ajout de la clé de session du client dans les liste des clés de client.
        afficher(f"<Système> Le client {infos_connexion[0]} c'est connecté."
                 f"\nEmpreinte de vérification: {empreinte_verif}")
        # Thread de réception pour chaque client.
        threading.Thread(target=reception, args=[connexion, infos_connexion, cle_session]).start()
        if not thread_envoi_lance:  # Lance l'unique thread d'envoi de message (et de commande).
            threading.Thread(target=thread_envoi).start()
            thread_envoi_lance = True
        # Relai aux autres clients le message de connexion.
        envoi_message(f"!!<Système> Le client {infos_connexion[0]} c'est connecté.",
                      co_reception=connexion, afficher_message=False)

else:  # Client.
    infos_connexion = (hote, arguments.port)
    connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    afficher_en_attente = True
    while True:  # Jusqu'à qu'une connexion soit créée.
        try:
            connexion.connect((hote, arguments.port))
            break
        except (ConnectionRefusedError, TimeoutError) as e:
            if afficher_en_attente:
                print(f"En attente du serveur ({hote}:{arguments.port})...   (Ctrl+C pour annuler)")
                afficher_en_attente = False
            time.sleep(0.2)
        except (socket.gaierror, OSError):
            raise SystemExit("Erreur: adresse invalide.")
        except OverflowError:
            raise SystemExit("Erreur: port invalide.")
    print("Échange sécurisé de la clé de session...")
    cle_privee = RSA.generate(CLE_RSA)  # Génération de la clé RSA.
    cle_publique = cle_privee.public_key()  # Génération de la clé publique avec la clé privée.
    cle_session = Random.get_random_bytes(CLE_SESSION)  # Génération de la clé de session.
    cle_publique_serveur = RSA.import_key(b64decode(connexion.recv(LEN_BUFFER_TCP)))  # Clé publique du serveur.
    if arguments.dev:  # Mode développeur.
        afficher("Échange sécurisé de la clé de session..."
                 f"[dev] Clé publique: {cle_publique.export_key('PEM')}"
                 f"\n[dev] Clé publique du serveur: {cle_publique_serveur.export_key('PEM')}"
                 f"\n[dev] Empreinte SHA256 de la clé de session: {SHA256.new(cle_session).hexdigest()}")
    # Signature de la clé de session hashée.
    signature_cle_session = pss.new(cle_privee).sign(SHA256.new(cle_session))
    # Chiffrement de la clé de session avec la clé publique du serveur.
    chiffrement_RSA_serveur = PKCS1_OAEP.new(cle_publique_serveur)
    cle_session_chiffree = chiffrement_RSA_serveur.encrypt(cle_session)
    # Envoi au client de la clé publique, la signature et la clé de session chiffrée. Reçu par le serveur ligne 324.
    connexion.sendall(b64encode(cle_publique.export_key("DER")) +
                      b64encode(signature_cle_session) +
                      b64encode(cle_session_chiffree))
    empreinte_verif = SHA256.new(cle_publique.export_key("DER") + cle_publique_serveur.export_key("DER")).hexdigest()
    afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}\n"
             f"Empreinte de vérification: {empreinte_verif}\n", notification=False)
    liste_connexions.append(connexion)  # Ajout du serveur à la liste des connexions actives.
    liste_cle_session.append(cle_session)  # Ajout de la clé de session à la liste des clés.
    # Lance l'unique thread de réception des messages du serveur.
    threading.Thread(target=reception, args=[connexion, (hote, arguments.port), cle_session]).start()
    thread_envoi()  # Execute la fonction (boucle) d'envoi des messages et commandes.
