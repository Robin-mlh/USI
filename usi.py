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
import readline
import base64
from urllib import error, request
from signal import signal, SIGINT

import tqdm
import plyer
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome import Random

LEN_BUFFER_TCP = 16384  # Taille du tampon socket en bits.
CLE_RSA = 2048  # Taille de la clé RSA en bits.
CLE_SESSION = 16  # Taille de la clé de session symétrique AES en octets.
USI_VERSION = "USI 2.1"

liste_ecran = []  # Liste des éléments à afficher.
liste_cle_session = []  # Liste des clés de session.
liste_connexions = []  # Liste des objets de connexions.
empreintes_verif = {}  # Dictionnaire des empreintes de vérifications.
quitter = False
message_annulation = True  # Si ctrl+c, afficher "Annulation" avec print.
if os.name == "nt":  # Pour Windows
    cls = "cls"
else:  # Pour linux
    cls = "clear"


def reception(connexion, infos_connexion, cle):
    """ Attend la réception d'un message en boucle. """

    while connexion in liste_connexions:
        try:
            message_recu_brut = connexion.recv(LEN_BUFFER_TCP)  # Attend la reception d'un message.
            if not message_recu_brut:  # Connexion désactivée.
                ferme_connexion(infos_connexion, message_client="<système> Erreur: connexion terminée.")
                break
            # Déchiffrement du message.
            donnees = [base64.b64decode(message_recu_brut[:20]),
                       base64.b64decode(message_recu_brut[20:44]),
                       base64.b64decode(message_recu_brut[44:])]
            objet_dechiffrement = AES.new(cle, AES.MODE_OCB, nonce=donnees[0])
            message_recu = objet_dechiffrement.decrypt_and_verify(donnees[2], donnees[1]).decode()
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {infos_connexion[0]} >> {message_recu} ({message_recu_brut.decode()})")
            if message_recu == "!client-fermeture" and arguments.serveur:  # Un client signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion)
            elif message_recu == "!serveur-fermeture" and not arguments.serveur:  # Le serveur signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion,
                                message_client="<système> Le serveur a fermé la connexion. ENTRÉE pour fermer.")
            elif message_recu == "!client-utilisateurs" and arguments.serveur:
                # Réponse du serveur pour la demande d'un client de la liste des utilisateurs.
                liste_utilisateurs = f"!utilisateurs >\n   Serveur: (ip_serveur) (empreinte_serveur)\n   Clients:"
                for co in liste_connexions:
                    if co == connexion:
                        liste_utilisateurs += f"\n            {co.getsockname()[0]}  (Vous)"
                    else:
                        liste_utilisateurs += f"\n            {co.getsockname()[0]}  ({empreintes_verif[co]})"
                envoi_message(liste_utilisateurs, co_unique=connexion, afficher_message=False)
            elif message_recu.startswith("!utilisateurs") and not arguments.serveur:
                # Traitement de la réponse du serveur contenant la liste des utilisateurs.
                liste_utilisateurs = message_recu.replace('(empreinte_serveur)', f'({empreintes_verif[connexion]})')
                afficher(f"{liste_utilisateurs.replace('(ip_serveur)', connexion.getsockname()[0])}")
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
                            barre_progression.close()
                            afficher()
                            break
                        f.write(bytes_recu)
                        barre_progression.update(len(bytes_recu))
                if arguments.serveur and len(liste_connexions) > 1:
                    envoi_fichier(fichier, co_reception=connexion, afficher_message=False)
            else:
                if message_recu.startswith(">>"):  # Système de citation.
                    message_temp = message_recu.split(">>")
                    citation = f"               \>{message_temp[1]}"
                    message_temp = ">>".join(message_temp[2:])
                    afficher(f"{infos_connexion[0]}>> {message_temp}\n{citation}")
                elif not arguments.dev and "<système>" not in message_recu:  # Message normal.
                    afficher(f"{infos_connexion[0]}>> {message_recu}")
                elif not arguments.dev:  # Message système.
                    afficher(message_recu)
                if arguments.serveur:
                    # Si serveur: relai aux autres clients du message (rechiffré par le serveur).
                    envoi_message(message_recu, co_reception=connexion,
                                  afficher_message=False)
        except (ConnectionResetError, ValueError, ConnectionAbortedError, OSError):
            ferme_connexion(infos_connexion, connexion, message_client="<système> Erreur: connexion terminée.")
            break


def thread_envoi():
    """ Demande le message à envoyer en boucle. """

    global liste_ecran

    if arguments.serveur:
        print()
    print("Appuyez sur ENTRÉE pour envoyer votre message.\nEn attente de message entrant...")
    while not quitter:
        msg_a_envoyer = input().rstrip()  # Demande le message à envoyer (ou la commande à executer).
        if msg_a_envoyer == "":  # Message vide: met à jour l'écran sans nouveau message.
            afficher(notification=False)
        elif msg_a_envoyer == "!cls":  # Supprimer les messages affichés.
            liste_ecran = []
            if arguments.serveur:
                afficher(f"Adresse ip locale: {ip_locale}   {ip_publique}   Port écouté: {arguments.port}\n",
                         notification=False)
            else:
                afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}\n"
                         f"Empreinte de vérification: {empreintes_verif[connexion]}\n", notification=False)
        elif msg_a_envoyer == "!quitter":  # Fermer la connexion.
            if arguments.serveur:
                envoi_message("!serveur-fermeture", afficher_message=False)
                ferme_connexion(message_client="\n<système> Déconnexion.")
            else:
                envoi_message("!client-fermeture", afficher_message=False)
                ferme_connexion(message_client="\n<système> Déconnexion et fermeture.")
        elif msg_a_envoyer == "!fichier":  # Envoi d'un fichier.
            fichier = input("Fichier à envoyer: ")
            if os.path.isfile(fichier):  # Vérification de l'éxistence du fichier.
                envoi_fichier(fichier)  # Envoi du fichier.
            else:
                print(f"<système> Le fichier '{fichier}' n'éxiste pas.")
        elif msg_a_envoyer == "!utilisateurs":  # Liste des utilisateurs.
            if not arguments.serveur:  # Demande la liste au serveur.
                envoi_message("!client-utilisateurs", afficher_message=False)
            else:  # Affiche la liste.
                liste_utilisateurs = (f"!utilisateurs >\n   Serveur: {sock.getsockname()[0]}  (Vous)"
                                      f"\n   Clients: {liste_connexions[0].getsockname()[0]}  "
                                      f"({empreintes_verif[liste_connexions[0]]})")
                for co in liste_connexions[1:]:
                    liste_utilisateurs += f"\n            {co.getsockname()[0]}  ({empreintes_verif[co]})"
                afficher(liste_utilisateurs)
        elif msg_a_envoyer in ["!help", "!aide", "!aled"]:  # Message d'aide des commandes.
            afficher(f"{msg_a_envoyer} >\n   Pour citer un message: '>>citation>>message'"
                     "\n   !quitter (ctrl+c)   Fermer la connexion"
                     "\n   !cls                Supprimer les messages affichés"
                     "\n   !fichier            Envoyer un fichier"
                     "\n   !utilisateurs       Afficher la liste des utilisateurs connectés", notification=False)
        else:  # Message normal.
            envoi_message(msg_a_envoyer, afficher_message=False)  # Chiffrement et envoi du message.
            if msg_a_envoyer.startswith(">>"):  # Système de citation.
                msg_a_envoyer = msg_a_envoyer.split(">>")
                citation = f"   \>{msg_a_envoyer[1]}"
                msg_a_envoyer = ">>".join(msg_a_envoyer[2:])
                afficher(f"{msg_a_envoyer}\n{citation}")
            elif not arguments.dev:
                afficher(msg_a_envoyer, notification=False)


def envoi_message(message, co_reception=None, co_unique=None, afficher_message=True):
    """ Envoi d'un message chiffré au(x) client(s). """

    if afficher_message and not arguments.dev:
        afficher(message, notification=False)
    for co, cle in zip(liste_connexions, liste_cle_session):
        if (not co_unique and co != co_reception) or co == co_unique:
            objet_chiffrement = AES.new(cle, AES.MODE_OCB)
            texte_chiffre, tag = objet_chiffrement.encrypt_and_digest(message.encode())
            message_chiffre = (f"{base64.b64encode(objet_chiffrement.nonce).decode()}"
                               f"{base64.b64encode(tag).decode()}"
                               f"{base64.b64encode(texte_chiffre).decode()}")
            co.sendall(message_chiffre.encode())  # Envoi du message chiffré.
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {message} ({message_chiffre}) >> {co.getsockname()}", notification=False)


def envoi_fichier(fichier, co_reception=None, afficher_message=True):
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


def ferme_connexion(infos_connexion=None, connexion=None, message_client=None):
    """ Ferme la connexion. """

    global liste_connexions
    global liste_cle_session
    global quitter

    if not quitter:
        if not connexion or not arguments.serveur:
            # Déconnexion totale et fermeture du programme.
            quitter = True
            if message_annulation:
                print("\n<système> Annulation.")
            else:
                afficher(message_client, notification=False)
            for co in liste_connexions:  # Fermeture de chaque connexion.
                co.shutdown(socket.SHUT_WR)
            liste_connexions, liste_cle_session = [], []
            exit(0)
        else:  # déconnexion d'un seul client.
            connexion.close()
            try:
                del liste_cle_session[liste_connexions.index(connexion)]
                liste_connexions.remove(connexion)
                afficher(f"<système> Le client {infos_connexion[0]} s'est déconnecté.")
                envoi_message(f"<système> Le client {infos_connexion[0]} s'est déconnecté.", afficher_message=False)
                if not liste_connexions:
                    print("\nEn attente de client...  ctrl+c pour quitter")
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
                plyer.notification.notify("USI serveur", contenu)
            else:
                plyer.notification.notify("USI client", contenu)
        except Exception:
            # Impossible d'envoyer une notification.
            pass


def signal_handler(signal, frame):
    """ Gestion du ctrl+c: ferme la connexion. """

    if arguments.serveur:  # Signalement de la déconnexion aux clients.
        envoi_message("!serveur-fermeture", afficher_message=False)
        ferme_connexion(message_client="\n<système> ctrl+c détecté: Déconnexion. ENTRÉE pour fermer.")
    else:
        envoi_message("!client-fermeture", afficher_message=False)
        ferme_connexion(message_client="\n<système> ctrl+c détecté: Déconnexion et fermeture.")


signal(SIGINT, signal_handler)  # Gestion du ctrl+c.
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
argumentParser.add_argument("-i", "--hote", required=False, metavar="HOTE", help="Spéficier le serveur à contacter."
                            " Uniquement en mode client\nIl peut par exemple sagir d'une IP. (défaut: localhost)")
argumentParser.add_argument("-p", "--port", type=int, required=False, default=12800,
                            help="Spécifier le port à utiliser (defaut: 12800)", metavar="PORT")
argumentParser.add_argument("-n", "--notifications", help="Désactiver les notifications", action="store_true")
argumentParser.add_argument("-d", "--dev", help="Mode développeur", action="store_true")
argumentParser.add_argument("-v", "--version", action='version', version=USI_VERSION,
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


# Mise en place de la connexion.
if arguments.serveur:  # Serveur.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", arguments.port))
    except OSError:
        raise SystemExit(f"Le port '{arguments.port}' est déjà utilisé.")
    try:  # Obtention de l'ip publique.
        ip_publique = f"Adresse ip publique: {json.loads(request.urlopen('http://httpbin.org/ip').read())['origin']}"
    except error.URLError:  # Adresse ip publique non disponible, vérifier la connexion.
        ip_publique = ""
    try:  # Obtention de l'ip locale.
        sock_ip_locale = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ip_locale.connect(('10.255.255.255', 1))
        ip_locale = sock.getsockname()[0]
    except Exception:
        ip_locale = "127.0.0.1"
    sock_ip_locale.close()
    afficher(f"Adresse ip locale: {ip_locale}   {ip_publique}   Port écouté: {arguments.port}\n", notification=False)
    sock.listen()
    sock.settimeout(0.5)
    thread_envoi_lance = False
    if not liste_connexions:
        print("En attente de client...  ctrl+c pour quitter")
    while not quitter:
        while not quitter:
            try:
                connexion, infos_connexion = sock.accept()  # Attend la connexion d'un client.
                break
            except (socket.timeout, OSError):
                pass
        if quitter:
            break
        message_annulation = False
        cle_privee = RSA.generate(CLE_RSA)  # Génération de la clé privée RSA.
        cle_publique = cle_privee.public_key()  # Obtention de la clé publique avec la clé privée.
        try:
            connexion.sendall(base64.b64encode(cle_publique.export_key("DER")))  # Envoi de la clé publique au client.
            message_recu = connexion.recv(LEN_BUFFER_TCP)
            cle_publique_client = RSA.import_key(base64.b64decode(message_recu[:392]))  # Clé publique du client.
            cle_session = PKCS1_OAEP.new(cle_privee).decrypt(base64.b64decode(message_recu[736:]))  # Clé de session.
        except (ValueError, ConnectionResetError):  # Le client a annulé la connexion.
            ferme_connexion(infos_connexion, connexion)
            continue
        if arguments.dev:  # Mode développeur.
            afficher("[dev] Échange sécurisé de la clé de session en cours..."
                     f"\n[dev] Clé publique: {cle_publique.export_key('PEM')}"
                     f"\n[dev] Clé publique du client: {cle_publique_client.export_key('PEM')}"
                     f"\n[dev] Empreinte SHA256 de la clé de session: {SHA256.new(cle_session).hexdigest()}")
        try:  # Vérification de la signature du client avec sa clé publique.
            pss.new(cle_publique_client).verify(SHA256.new(cle_session), base64.b64decode(message_recu[392:736]))
        except (ValueError, TypeError):  # Echec de la vérification de l'authenticité de la signature.
            afficher(f"<système> Connexion du client {infos_connexion[0]} refusée car sa "
                     "signature est invalide. Son identité est peut être usurpée.\n")
            ferme_connexion(infos_connexion, connexion)
            continue
        liste_connexions.append(connexion)  # Ajout de la connexion à la liste des connexions actives.
        liste_cle_session.append(cle_session)  # Ajout de la clé de session du client dans la liste des clés de client.
        empreintes_verif[connexion] = SHA256.new(cle_publique_client.export_key("DER") +
                                                 cle_publique.export_key("DER")).hexdigest()
        # Thread de réception pour chaque client.
        threading.Thread(target=reception, args=[connexion, infos_connexion, cle_session]).start()
        if not thread_envoi_lance:  # Lance l'unique thread d'envoi de message (et de commande).
            threading.Thread(target=thread_envoi).start()
            thread_envoi_lance = True
        envoi_message(f"<système> Le client {infos_connexion[0]} c'est connecté."
                      f"\nEmpreinte de vérification: {empreintes_verif[connexion]}", co_reception=connexion)

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
                print(f"En attente du serveur ({hote}:{arguments.port})...   ctrl+c pour quitter")
                afficher_en_attente = False
            time.sleep(0.2)
        except (socket.gaierror, OSError):
            raise SystemExit(f"Adresse '{hote}' invalide.")
        except OverflowError:
            raise SystemExit(f"Port '{arguments.port}' invalide.")
    message_annulation = False
    print("Échange sécurisé de la clé de session...")
    cle_privee = RSA.generate(CLE_RSA)  # Génération de la clé RSA.
    cle_publique = cle_privee.public_key()  # Génération de la clé publique avec la clé privée.
    cle_session = Random.get_random_bytes(CLE_SESSION)  # Génération de la clé de session.
    try:  # Reception de la clé publique du serveur.
        cle_publique_serveur = RSA.import_key(base64.b64decode(connexion.recv(LEN_BUFFER_TCP)))
    except (ConnectionResetError, ValueError):
        raise SystemExit("<système> Le serveur a fermé la connexion.")
    if arguments.dev:  # Mode développeur.
        afficher("Échange sécurisé de la clé de session..."
                 f"\n[dev] Clé publique: {cle_publique.export_key('PEM')}"
                 f"\n[dev] Clé publique du serveur: {cle_publique_serveur.export_key('PEM')}"
                 f"\n[dev] Empreinte SHA256 de la clé de session: {SHA256.new(cle_session).hexdigest()}")
    # Signature de la clé de session hashée.
    signature_cle_session = pss.new(cle_privee).sign(SHA256.new(cle_session))
    # Chiffrement de la clé de session avec la clé publique du serveur.
    chiffrement_RSA_serveur = PKCS1_OAEP.new(cle_publique_serveur)
    cle_session_chiffree = chiffrement_RSA_serveur.encrypt(cle_session)
    # Envoi au client de la clé publique, la signature et la clé de session chiffrée.
    connexion.sendall(base64.b64encode(cle_publique.export_key("DER")) +
                      base64.b64encode(signature_cle_session) +
                      base64.b64encode(cle_session_chiffree))
    liste_connexions.append(connexion)  # Ajout du serveur à la liste des connexions actives.
    liste_cle_session.append(cle_session)  # Ajout de la clé de session à la liste des clés.
    empreintes_verif[connexion] = SHA256.new(cle_publique.export_key("DER") +
                                             cle_publique_serveur.export_key("DER")).hexdigest()
    afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}\n"
             f"Empreinte de vérification: {empreintes_verif[connexion]}\n", notification=False)
    # Lance l'unique thread de réception des messages du serveur.
    threading.Thread(target=reception, args=[connexion, (hote, arguments.port), cle_session]).start()
    thread_envoi()  # Execute la fonction (boucle) d'envoi des messages et commandes.
