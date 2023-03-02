#!/usr/bin/python3

""" Communications simples et chiffrées. """

import sys
import time
import threading
import socket
import json
import argparse
import os
if os.name == "nt":  # Windows
    pass
else:  # linux
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
USI_VERSION = "USI 2.3"  # Version d'USI, pour l'option --version.

liste_ecran = []  # Liste des éléments à afficher.
liste_cle_session = []  # Liste des clés de session.
liste_connexions = []  # Liste des objets de connexions.
empreintes_verif = {}  # Dictionnaire des empreintes de vérifications.
quitter = False
message_annulation = True  # Si ctrl+c, afficher "Annulation" avec print.
input_reponse = False  # Si différent de False, le thread Reception attend la réponse de l'input.
if os.name == "nt":  # Pour Windows
    cls = "cls"
else:  # Pour linux
    cls = "clear"


def reception(connexion, infos_connexion, cle):
    """ Attend la réception d'un message en boucle. """

    global input_reponse

    while connexion in liste_connexions:
        try:
            message_recu_brut = connexion.recv(LEN_BUFFER_TCP)  # Attend la reception d'un message.
            if not message_recu_brut:
                if arguments.serveur:  # Connexion désactivée par un client: déconnexion du client.
                    ferme_connexion(infos_connexion, connexion)
                    continue
                else:  # Connexion désactivée par le serveur: fermeture du programme.
                    ferme_connexion(infos_connexion,
                                    message_client="<système> Connexion terminée par le serveur. ENTRÉE pour fermer.")
                    break
            # Déchiffrement du message.
            objet_dechiffrement = AES.new(cle, AES.MODE_OCB, nonce=base64.b64decode(message_recu_brut[:20]))
            try:
                message_recu = objet_dechiffrement.decrypt_and_verify(base64.b64decode(message_recu_brut[44:]),
                                                                      base64.b64decode(message_recu_brut[20:44])).decode()
            except ValueError:
                message_recu = "[Message reçu impossible à déchiffrer]"
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {infos_connexion[0]} >> {message_recu} ({message_recu_brut.decode()})")
            if message_recu == "!client-fermeture" and arguments.serveur:  # Un client signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion)
            elif message_recu == "!serveur-fermeture" and not arguments.serveur:  # Le serveur signal sa déconnexion.
                ferme_connexion(infos_connexion, connexion,
                                message_client="<système> Le serveur a fermé la connexion. ENTRÉE pour fermer.")
            elif message_recu == "!client-utilisateurs" and arguments.serveur:
                # Réponse du serveur pour la demande d'un client de la liste des utilisateurs.
                liste_utilisateurs = ""
                for co in liste_connexions:
                    if co == connexion:
                        liste_utilisateurs += f"\n            {co.getpeername()[0]}  (Vous)"
                    else:
                        liste_utilisateurs += f"\n            {co.getpeername()[0]}  ({empreintes_verif[co]})"
                liste_utilisateurs = ''.join(("!utilisateurs >\n   Serveur: (ip_serveur) (empreinte_serveur)"
                                              "\n   Clients:", liste_utilisateurs[12:]))
                envoi_message(liste_utilisateurs, co_unique=connexion, afficher_message=False)
            elif message_recu.startswith("!utilisateurs") and not arguments.serveur:
                # Traitement de la réponse du serveur contenant la liste des utilisateurs.
                liste_utilisateurs = message_recu.replace('(empreinte_serveur)', f'({empreintes_verif[connexion]})')
                afficher(f"{liste_utilisateurs.replace('(ip_serveur)', hote)}")
            elif message_recu.startswith("!:f"):  # Reception et déchiffrement d'un fichier.
                nom_fichier, taille_fichier = message_recu[3:].split("|")
                afficher(f"{infos_connexion[0]}>> [Fichier {nom_fichier} - {taille_fichier}o]")
                afficher("<système> Voulez-vous télécharger ce fichier ? (O/n)")
                if os.path.exists(nom_fichier):  # Un fichier du même nom existe deja.
                    afficher(f"<système> Attention: le fichier '{nom_fichier}' existe déjà.")
                input_reponse = True
                while input_reponse is True:  # Attend que le thread d'envois et son input définisse la input_reponse.
                    pass
                try:
                    if input_reponse in ["o", "oui", "O", "y", "yes", ""]:
                        # Création de la barre de progression du téléchargement du fichier.
                        barre_progression = tqdm.tqdm(range(int(taille_fichier)), f"Réception fichier",
                                                      unit="o", unit_scale=True)
                        donnees_recu = bytearray()
                        while True:  # Réception et enregistrement des paquets du fichier.
                            bytes_recu = connexion.recv(LEN_BUFFER_TCP)
                            if b"|!f|" in bytes_recu:
                                bytes_recu = bytes_recu.split(b"|!f|")[0]
                                donnees_recu += bytes_recu
                                break
                            barre_progression.update(LEN_BUFFER_TCP)
                            donnees_recu += bytes_recu
                        try:  # Déchiffrement du fichier.
                            objet_dechiffrement = AES.new(cle, AES.MODE_OCB, nonce=bytes(donnees_recu[:15]))
                            contenu_fichier = objet_dechiffrement.decrypt_and_verify(bytes(donnees_recu[31:]),
                                                                                     bytes(donnees_recu[15:31]))
                        except ValueError:
                            barre_progression.close()
                            afficher("<système> Erreur: Impossible de déchiffrer le fichier reçu.")
                        else:
                            with open(nom_fichier, "wb") as f:  # Écriture du fichier déchiffré.
                                f.write(contenu_fichier)
                            barre_progression.close()
                            afficher(f"<système> Fichier {nom_fichier} téléchargé.")
                    else:  # Le téléchargement est refusé. Recevoir les paquets du fichier sans l'enregistrer.
                        while b"|!f|" not in connexion.recv(LEN_BUFFER_TCP):
                            pass
                        afficher(f"<système> Fichier {nom_fichier} non téléchargé.")
                    input_reponse = False
                    # Le serveur partage le fichier aux autres clients.
                    if arguments.serveur and len(liste_connexions) > 1:
                        afficher(f"<système> Distribution du fichier aux autres clients...", notification=False)
                        try:
                            envoi_fichier(nom_fichier, int(taille_fichier),
                                          co_reception=connexion, afficher_message=False)
                        except Exception as e:
                            afficher(f"<système> Erreur lors du partage du fichier {nom_fichier} aux clients: {e}.",
                                     notification=False)
                except Exception as e:
                    afficher(f"<système> Erreur lors de la réception du fichier: {e}.",
                             notification=False)
            else:
                if "<système>" in message_recu and not arguments.dev:  # Message système.
                    afficher(message_recu)
                elif message_recu.startswith("!:s") and not arguments.dev:  # Client: Message normal.
                    afficher(message_recu[3:])
                elif not arguments.dev:  # Serveur: Message normal.
                    afficher(f"{infos_connexion[0]}>> {message_recu}")
                if arguments.serveur and len(liste_connexions) > 1:  # relai aux autres clients du message.
                    envoi_message(f"!:s{infos_connexion[0]}>> {message_recu}", co_reception=connexion,
                                  afficher_message=False)
        except (ConnectionResetError, ValueError, ConnectionAbortedError, OSError) as e:
            ferme_connexion(infos_connexion, connexion, message_client=f"<système> Erreur: {e}. Connexion terminée, "
                                                                       "ENTRÉE pour fermer.")
            break


def thread_envoi():
    """ Demande le message à envoyer en boucle. """

    global liste_ecran
    global input_reponse

    if arguments.serveur:
        print()
    print("Appuyez sur ENTRÉE pour envoyer votre message.\nEn attente de message entrant...")
    while not quitter:
        msg_a_envoyer = input().rstrip()  # Demande le message à envoyer (ou la commande à exécuter).
        if msg_a_envoyer.startswith("!:s"):
            msg_a_envoyer = msg_a_envoyer[3:]
        if input_reponse:
            input_reponse = msg_a_envoyer
            afficher(msg_a_envoyer, notification=False)
        elif msg_a_envoyer == "":  # Message vide: met à jour l'écran sans nouveau message.
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
        elif msg_a_envoyer.startswith("!fichier"):  # Envoi d'un fichier.
            if msg_a_envoyer == "!fichier":  # Pas le nom du fichier dans la commande: "!fichier"
                afficher("<système> Quel est le nom du fichier à envoyer ?")
                nom_fichier = input()
                afficher(nom_fichier)
            else:  # Nom du fichier dans la commande: "!fichier LE_FICHIER"
                nom_fichier = msg_a_envoyer[9:]
            try:  # Obtention de la taille du fichier et vérification de son existence.
                taille_fichier = os.path.getsize(nom_fichier)
                if taille_fichier > 2400000000:
                    afficher(f"<système> Erreur: Le fichier est trop lourd pour être envoyé (>2.4go).",
                             notification=False)
                else:
                    try:
                        envoi_fichier(nom_fichier, taille_fichier)  # Envoi du fichier.
                    except Exception as e:
                        afficher(f"<système> Erreur lors de l'envoi du fichier: {e}.", notification=False)
            except OSError:
                afficher(f"<système> Le fichier '{nom_fichier}' n'existe pas.")
        elif msg_a_envoyer == "!utilisateurs":  # Liste des utilisateurs.
            if not arguments.serveur:  # Demande la liste au serveur.
                envoi_message("!client-utilisateurs", afficher_message=False)
            else:  # Affiche la liste.
                liste_utilisateurs = ""
                for co in liste_connexions:
                    liste_utilisateurs += f"\n            {co.getpeername()[0]}  ({empreintes_verif[co]})"
                liste_utilisateurs = ''.join((f"!utilisateurs >\n   Serveur: (Vous)\n   Clients:",
                                              liste_utilisateurs[12:]))
                afficher(liste_utilisateurs)
        elif msg_a_envoyer in ["!help", "!aide", "!aled"]:  # Message d'aide des commandes.
            afficher(f"{msg_a_envoyer} >\n   !quitter / Ctrl+C   Fermer la connexion"
                     "\n   !cls                Supprimer les messages affichés"
                     "\n   !fichier FICHIER    Envoyer un fichier"
                     "\n   !utilisateurs       Afficher la liste des utilisateurs connectés", notification=False)
        else:  # Message normal.
            envoi_message(msg_a_envoyer, afficher_message=False)  # Chiffrement et envoi du message.
            if not arguments.dev:
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
                afficher(f"[dev] {message} ({message_chiffre}) >> {co.getpeername()}", notification=False)


def envoi_fichier(nom_fichier, taille_fichier, co_reception=None, afficher_message=True):
    """ Chiffrement et envoi d'un fichier. """

    with open(nom_fichier, "rb") as f:  # Lecture du fichier à envoyer.
        contenu_fichier = f.read()
    for co, cle in zip(liste_connexions, liste_cle_session):  # Envois du fichier à chaque connexion.
        if co != co_reception:
            print("Chiffrement...")
            # Création de la barre de progression de l'envois du fichier.
            barre_progression = tqdm.tqdm(range(taille_fichier), "Envoi fichier", unit="o", unit_scale=True)
            objet_chiffrement = AES.new(cle, AES.MODE_OCB)  # Chiffrement du fichier avec la clé de la connexion.
            fichier_chiffre, tag = objet_chiffrement.encrypt_and_digest(contenu_fichier)
            donnees_chiffre = objet_chiffrement.nonce + tag + fichier_chiffre
            # Envois du message de signalement d'envois d'un fichier avec le nom et la taille du fichier.
            envoi_message(f"!:f{os.path.basename(nom_fichier)}|{taille_fichier}",
                          co_unique=co, afficher_message=False)
            afficher(notification=False)
            print(f"<système> En attente de réponse de {co.getpeername()[0]}...")
            xp = 0
            while True:  # Envois du fichier sous forme de paquets d'une longueur de LEN_BUFFER_TCP.
                if (xp*LEN_BUFFER_TCP)+LEN_BUFFER_TCP > len(donnees_chiffre):
                    # Il ne reste plus assez de données à envoyer pour envoyer un paquet complet.
                    co.sendall(donnees_chiffre[xp*LEN_BUFFER_TCP:])
                    break
                else:  # Paquet complet.
                    co.sendall(donnees_chiffre[xp * LEN_BUFFER_TCP:(xp * LEN_BUFFER_TCP) + LEN_BUFFER_TCP])
                barre_progression.update(LEN_BUFFER_TCP)
                xp += 1
            co.sendall(b"|!f|")  # Signalement de la fin des envois de paquets du fichier.
            barre_progression.close()
            afficher(notification=False)
    if afficher_message:
        afficher(f"[Fichier {nom_fichier} - {taille_fichier}o]", notification=False)


def ferme_connexion(infos_connexion=None, connexion=None, message_client=None):
    """ Ferme la connexion. """

    global liste_connexions
    global liste_cle_session
    global quitter

    if not quitter:
        if not connexion or not arguments.serveur:  # Déconnexion totale et fermeture du programme.
            quitter = True
            if message_annulation:
                print("\n<système> Annulation.")
            else:
                afficher(message_client, notification=False)
            for co in liste_connexions:  # Fermeture de chaque connexion.
                try:
                    co.shutdown(socket.SHUT_WR)
                except OSError:  # La connexion est deja fermée.
                    pass
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
        if notification and arguments.notifications:  # Notification.
            try:
                if arguments.serveur:
                    plyer.notification.notify("USI serveur", nouvel_element)
                else:
                    plyer.notification.notify("USI client", nouvel_element)
            except Exception:
                pass
    os.system(cls)  # Nettoyage de l'écran.
    for element in liste_ecran:  # Affiche chaque élément.
        print(element)


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
argumentParser = argparse.ArgumentParser(description="USI: Communications simples et chiffrées."
                                                     " github.com/Robin-mlh/USI\nUne fois connecté, "
                                                     "entrez '!aide' pour afficher les commandes disponibles.",
                                         usage="usi.py [-dhn] { -s | -c [HOTE[:PORT]] } [-p PORT]",
                                         formatter_class=argparse.RawTextHelpFormatter, add_help=False)
argumentParser._optionals.title = 'Options'
group = argumentParser.add_mutually_exclusive_group(required=True)
group.add_argument('-s', "--serveur", action='store_true',
                   help="Utiliser le mode serveur pour attendre des clients")
group.add_argument('-c', "--client", metavar="HOTE[:PORT]", nargs="?", default=False,
                   help="Utiliser le mode client pour se connecter à un serveur\n"
                        "Option: Spécifier l'adresse du serveur (défaut: localhost)")
argumentParser.add_argument("-p", "--port", type=int, default=12800, metavar="PORT",
                            help="Spécifier le port à utiliser (defaut: 12800)")
argumentParser.add_argument("-k", "--cle", type=str, metavar="CLE",
                            help="Spécifier une clé de session de 128, 192 ou 256 bits\n"
                                 "La clé doit être encodée en base64 ou en hexadecimal")
argumentParser.add_argument("-n", "--notifications", help="Activer les notifications", action="store_true")
argumentParser.add_argument("-d", "--dev", help="Mode développeur", action="store_true")
argumentParser.add_argument("-v", "--version", action='version', version=USI_VERSION,
                            help="Afficher la version")
argumentParser.add_argument("-h", "--help", action="help", help="Afficher ce message d'aide")
if len(sys.argv) == 1:  # Affiche l'aide si USI est lancé sans arguments.
    argumentParser.print_help(sys.stderr)
    sys.exit(1)
arguments = argumentParser.parse_args()
if not arguments.client:
    hote = "localhost"  # Hôte par défaut.
else:
    rfind_port = arguments.client.rfind(":")
    if rfind_port >= 0:  # Si un port est spécifié dans le nom d'hôte.
        arguments.port = int(arguments.client[rfind_port+1:])  # Utiliser le port trouvé dans le nom d'hôte.
        arguments.client = arguments.client[:rfind_port]  # Enlever le port dans le nom d'hôte.
    hote = arguments.client

# Chargement de la clé de session spécifiée par l'utilisateur.
if arguments.cle:
    try:  # Hexadecimal
        cle_session = base64.b16decode(arguments.cle.upper())
    except ValueError:
        try:  # Base64
            data = base64.b64decode(arguments.cle.upper())
        except ValueError:
            raise SystemExit(f"La clé doit être encodée en base64 ou en hexadecimal.")

# Mise en place de la connexion.
if arguments.serveur:  # Serveur.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", arguments.port))
    except OSError:
        raise SystemExit(f"Le port {arguments.port} est déjà utilisé.")
    try:  # Obtention de l'ip publique.
        ip_publique = f"Adresse ip publique: {json.loads(request.urlopen('https://httpbin.org/ip').read())['origin']}"
    except error.URLError:  # Adresse ip publique non disponible, vérifier la connexion.
        ip_publique = ""
    try:  # Obtention de l'ip locale.
        sock_ip_locale = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_ip_locale.connect(('1.1.1.1', 80))
        ip_locale = sock_ip_locale.getsockname()[0]
    except socket.error:
        try:
            ip_locale = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            ip_locale = "127.0.0.1"
    sock_ip_locale.close()
    afficher(f"Adresse ip locale: {ip_locale}   {ip_publique}   Port écouté: {arguments.port}\n", notification=False)
    sock.listen()
    sock.settimeout(0.5)
    thread_envoi_lance = False
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
        if not arguments.cle:  # Si l'utilisateur n'a pas deja chargé de clé de session.
            cle_privee = RSA.generate(CLE_RSA)  # Génération de la clé privée RSA.
            cle_publique = cle_privee.public_key()  # Obtention de la clé publique avec la clé privée.
            try:
                connexion.sendall(base64.b64encode(cle_publique.export_key("DER")))
                message_recu = connexion.recv(LEN_BUFFER_TCP)
                cle_publique_client = RSA.import_key(base64.b64decode(message_recu[:392]))
                cle_session = PKCS1_OAEP.new(cle_privee).decrypt(base64.b64decode(message_recu[736:]))
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
            # Génération de l'empreinte SHA256 de vérification de l'authenticité de la connexion.
            empreintes_verif[connexion] = SHA256.new(cle_publique_client.export_key("DER") +
                                                     cle_publique.export_key("DER")).hexdigest()
        else:
            empreintes_verif[connexion] = SHA256.new(cle_session).hexdigest()
        liste_connexions.append(connexion)  # Ajout de la connexion à la liste des connexions actives.
        liste_cle_session.append(cle_session)  # Ajout de la clé de session du client dans la liste des clés de client.
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
    print(f"Connexion à {hote}:{arguments.port}...   ctrl+c pour annuler")
    afficher_en_attente = True
    while True:  # Jusqu'à qu'une connexion soit créée.
        try:
            connexion.connect((hote, arguments.port))
            break
        except (ConnectionRefusedError, TimeoutError) as e:
            if afficher_en_attente:
                afficher(f"En attente du serveur ({hote}:{arguments.port})...   ctrl+c pour quitter",
                         notification=False)
                afficher_en_attente = False
            time.sleep(0.2)
        except (socket.gaierror, OSError):
            raise SystemExit(f"Adresse {hote} invalide.")
        except OverflowError:
            raise SystemExit(f"Port {arguments.port} invalide.")
    message_annulation = False
    if not arguments.cle:  # Si l'utilisateur n'a pas deja chargé de clé de session.
        afficher("Échange sécurisé de la clé de session...", notification=False)
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
        # Génération de l'empreinte SHA256 de vérification de l'authenticité de la connexion.
        empreintes_verif[connexion] = SHA256.new(cle_publique.export_key("DER") +
                                                 cle_publique_serveur.export_key("DER")).hexdigest()
    else:
        empreintes_verif[connexion] = SHA256.new(cle_session).hexdigest()
    liste_connexions.append(connexion)  # Ajout du serveur à la liste des connexions actives.
    liste_cle_session.append(cle_session)  # Ajout de la clé de session à la liste des clés.
    liste_ecran = []  # Réinitialise l'écran.
    afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}\n"
             f"Empreinte de vérification: {empreintes_verif[connexion]}\n", notification=False)
    # Lance l'unique thread de réception des messages du serveur.
    threading.Thread(target=reception, args=[connexion, (hote, arguments.port), cle_session]).start()
    thread_envoi()  # Execute la fonction (boucle) d'envoi des messages et commandes.
