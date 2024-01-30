#!/usr/bin/python3

""" Système de communication TCP via socket sécurisé. """

import sys
import time
import threading
import socket
import json
import argparse
import os
import base64
import getpass
from urllib import error, request
from signal import signal, SIGINT
try:
    import readline
except ImportError:
    pass

import tqdm
import plyer
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import bcrypt, bcrypt_check
from Cryptodome import Random

LEN_BUFFER_TCP = 16384  # Taille du tampon socket en bits.
CLE_RSA_BITS = 2048  # Taille de la clé RSA en bits à générer par défaut.
CLE_SESSION = 16  # Taille de la clé de session symétrique AES en octets à générer par défaut.
USI_VERSION = "USI 2.4"  # Version d'USI, pour l'option --version.

liste_ecran = []  # Liste des éléments à afficher.
data_connexions_list = []  # Liste des informations de chaque connexion active. Voir ci dessous:
# [[socket_connexion, hote, nom_pseudo, cle_session, empreinte_verif], ...]
quitter = False
message_annulation = True  # Si ctrl+c, afficher "Annulation" avec print.
input_reponse = False  # Si différent de False, le thread Reception attend la réponse de l'input.
password_a_test = ""  # Mot de passe saisi par le client pour vérifier l'authenticité du serveur.
message_input = ""  # Message à afficher en bas de tous les autres messages. Il est la question des input.
if os.name == "nt":  # Pour Windows
    cls = "cls"
else:  # Pour linux
    cls = "clear"


def reception(data_co):
    """ Attend la réception d'un message en boucle. """

    global input_reponse
    global password_a_test
    global message_input

    while any(data_co[0] in coliste for coliste in data_connexions_list):
        try:
            message_recu_brut = data_co[0].recv(LEN_BUFFER_TCP)  # Attend la reception d'un message.
            if not message_recu_brut:
                if arguments.serveur:  # Connexion désactivée par un client: déconnexion du client.
                    ferme_connexion(data_co)
                    continue
                else:  # Connexion désactivée par le serveur: fermeture du programme.
                    ferme_connexion(data_co,
                                    message_client="<système> Connexion terminée par le serveur. ENTRÉE pour fermer.")
                    break
            # Déchiffrement du message.
            objet_dechiffrement = AES.new(data_co[3], AES.MODE_OCB, nonce=base64.b64decode(message_recu_brut[:20]))
            try:
                message_recu = objet_dechiffrement.decrypt_and_verify(base64.b64decode(message_recu_brut[44:]),
                                                                      base64.b64decode(message_recu_brut[20:44])).decode()
            except ValueError:
                message_recu = f"[Message reçu impossible à déchiffrer]"
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {data_co[1]} >> {message_recu} ({message_recu_brut.decode()})")
            if message_recu == "|!client-fermeture" and arguments.serveur:  # Un client signal sa déconnexion.
                ferme_connexion(data_co)
            elif message_recu == "|!serveur-fermeture" and not arguments.serveur:  # Le serveur signal sa déconnexion.
                ferme_connexion(data_co, message_client=f"<système> Le serveur {data_co[2]}"
                                                        " a fermé la connexion. ENTRÉE pour fermer.")
            elif message_recu == "!client-utilisateurs" and arguments.serveur:
                # Réponse du serveur pour la demande d'un client de la liste des utilisateurs.
                liste_utilisateurs = ""
                for data_user in data_connexions_list:
                    if data_user[0] == data_co[0]:
                        liste_utilisateurs += f"\n            {data_co[1]} {data_co[2]} (Vous)"
                    else:
                        liste_utilisateurs += f"\n            {data_co[1]} {data_user[2]} ({data_user[4]})"
                liste_utilisateurs = ''.join(("!utilisateurs >\n   Serveur: (ip_serveur) (pseudo) (empreinte_serveur)"
                                              "\n   Clients:", liste_utilisateurs[12:]))
                envoi_message(liste_utilisateurs, co_unique=data_co[0], afficher_message=False)
            elif message_recu.startswith("!utilisateurs") and not arguments.serveur:
                # Traitement de la réponse du serveur contenant la liste des utilisateurs.
                liste_utilisateurs = message_recu.replace('(empreinte_serveur)', f'({data_connexions_list[0][4]})')
                liste_utilisateurs = liste_utilisateurs.replace('(pseudo)', f'{data_connexions_list[0][2]}')
                afficher(f"{liste_utilisateurs.replace('(ip_serveur)', hote)}")
            elif message_recu == "|!challenge-mdp-1" and arguments.serveur:
                # Requête d'authentification reçue par le serveur.
                afficher(f"<système> Le client {data_co[1]} vous demande de prouver votre authenticité.")
                message_input = "Saisissez le mot de passe: "
                afficher()
                input_reponse = True
                while input_reponse is True:  # Attend que le thread d'envois et son input définisse la input_reponse.
                    pass
                # Hash du mot de passe saisi et envoi du hash au client qui a demandé la vérification.
                bcrypt_hash = bcrypt(base64.b64encode(SHA256.new(input_reponse.encode()).digest()), 12).decode()
                envoi_message(f"|!challenge-mdp-2:{bcrypt_hash}", co_unique=data_co[0], afficher_message=False)
                message_input, input_reponse = "", False
            elif message_recu.startswith("|!challenge-mdp-2:"):
                # Réponse du serveur reçue par le client à la requête d'authentification.
                hash_recu = message_recu[18:].encode()  # Récupère le hash envoyé par le serveur.
                try:  # Vérifier que le hash du mot de passe attendu et le hash envoyé par le client correspondent.
                    bcrypt_check(base64.b64encode(SHA256.new(password_a_test.encode()).digest()), hash_recu)
                except ValueError:
                    afficher(f"<système> /!\\ Le serveur n'a pas entré le même mot de passe.")
                else:
                    afficher(f"<système> Le serveur a entré le bon mot de passe.")
            elif message_recu.startswith("|!f"):  # Reception et déchiffrement d'un fichier.
                nom_fichier, taille_fichier = message_recu[3:].split("|")
                afficher(f"{data_co[1]}>> [Fichier {nom_fichier} - {taille_fichier}o]")
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
                            bytes_recu = data_co[0].recv(LEN_BUFFER_TCP)
                            if b"|!f|" in bytes_recu:
                                bytes_recu = bytes_recu.split(b"|!f|")[0]
                                donnees_recu += bytes_recu
                                break
                            barre_progression.update(LEN_BUFFER_TCP)
                            donnees_recu += bytes_recu
                        try:  # Déchiffrement du fichier.
                            objet_dechiffrement = AES.new(data_co[3], AES.MODE_OCB, nonce=bytes(donnees_recu[:15]))
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
                        while b"|!f|" not in data_co[0].recv(LEN_BUFFER_TCP):
                            pass
                        afficher(f"<système> Fichier {nom_fichier} non téléchargé.")
                    input_reponse = False
                    # Le serveur partage le fichier aux autres clients.
                    if arguments.serveur and len(data_connexions_list) > 1:
                        afficher(f"<système> Distribution du fichier aux autres clients...",
                                 notification=False)
                        try:
                            envoi_fichier(nom_fichier, int(taille_fichier),
                                          co_reception=data_co[0], afficher_message=False)
                        except Exception as e:
                            afficher(f"<système> Erreur lors du partage du fichier {nom_fichier} aux clients: {e}.",
                                     notification=False)
                except Exception as e:
                    afficher(f"<système> Erreur lors de la réception du fichier: {e}.",
                             notification=False)
            else:
                if data_co[2]:
                    nom_avec_espace = f" {data_co[2]}"
                else:
                    nom_avec_espace = ""
                if "<système>" in message_recu and not arguments.dev:  # Message système.
                    afficher(message_recu)
                elif message_recu.startswith("|!r") and not arguments.dev:  # Client: Message normal.
                    afficher(message_recu[3:])
                elif not arguments.dev:  # Serveur: Message normal.
                    afficher(f"{data_co[1]}{nom_avec_espace}>> {message_recu}")
                if arguments.serveur and len(data_connexions_list) > 1:  # Relai aux autres clients du message.
                    envoi_message(f"|!r{data_co[1]}{nom_avec_espace}>> {message_recu}",
                                  co_reception=data_co[0], afficher_message=False)
        except (ConnectionResetError, ValueError, ConnectionAbortedError, OSError) as e:
            ferme_connexion(data_co, message_client=f"<système> Erreur: {e}. Connexion terminée, ENTRÉE pour fermer.")
            break


def thread_envoi():
    """ Demande le message à envoyer en boucle. """

    global liste_ecran
    global input_reponse
    global password_a_test
    global message_input

    if arguments.serveur:
        print()
    print("Appuyez sur ENTRÉE pour envoyer votre message.\nEn attente de message entrant...")
    while not quitter:
        msg_a_envoyer = input().rstrip()  # Demande le message à envoyer (ou la commande à exécuter).
        if msg_a_envoyer.startswith("|!r"):
            msg_a_envoyer = msg_a_envoyer[3:]
        if input_reponse:
            input_reponse = msg_a_envoyer
        elif msg_a_envoyer == "":  # Message vide: met à jour l'écran sans nouveau message.
            afficher(notification=False)
        elif msg_a_envoyer == "!cls":  # Supprimer les messages affichés.
            liste_ecran = []
            if arguments.serveur:
                afficher(f"Adresse ip locale: {ip_locale}   {ip_publique}"
                         f"   Port écouté: {arguments.port}   {nom_affiche}\n", notification=False)
            else:
                if nom_serveur:
                    nom_client = f" ({nom_serveur})"
                afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}{nom_client}"
                         f"   {nom_affiche}\nEmpreinte de vérification: {empreintes_verif}\n",
                         notification=False)
        elif msg_a_envoyer == "!quitter":  # Fermer la connexion.
            if arguments.serveur:
                envoi_message("|!serveur-fermeture", afficher_message=False)
                ferme_connexion(message_client="\n<système> Déconnexion.")
            else:
                envoi_message("|!client-fermeture", afficher_message=False)
                ferme_connexion(message_client="\n<système> Déconnexion et fermeture.")
        elif msg_a_envoyer.startswith("!fichier"):  # Envoi d'un fichier.
            if msg_a_envoyer == "!fichier":  # Pas le nom du fichier dans la commande: "!fichier"
                message_input = "<système> Quel est le nom du fichier à envoyer ?"
                afficher()
                nom_fichier = input()
                message_input = ""
            else:  # Nom du fichier dans la commande: "!fichier LE_FICHIER"
                nom_fichier = msg_a_envoyer[9:]
            try:  # Obtention de la taille du fichier et vérification de son existence.
                taille_fichier = os.path.getsize(nom_fichier)
                if taille_fichier > 2400000000:
                    afficher(f"<système> Erreur: Le fichier est trop lourd pour être envoyé (>2.4Gb).",
                             notification=False)
                else:
                    try:
                        envoi_fichier(nom_fichier, taille_fichier)  # Envoi du fichier.
                    except Exception as e:
                        afficher(f"<système> Erreur lors de l'envoi du fichier: {e}.", notification=False)
            except OSError:
                afficher(f"<système> Le fichier '{nom_fichier}' n'existe pas.")
        elif msg_a_envoyer == "!motdepasse":  # Commande de requête d'authentification.
            if arguments.serveur:
                afficher("<système> La commande !motdepasse n'est pas disponible pour le serveur.")
            else:  # Saisie du mot de passe que devra entrer le serveur et envoi de la demande d'authentification.
                afficher("<système> Un mot de passe sera demandé à "
                         f"{data_connexions_list[0][1]} pour vérifier son authenticité.")
                message_input = "<système> Entrez le mot de passe que le serveur devra saisir: "
                afficher()
                password_a_test = getpass.getpass("")
                message_input = ""
                envoi_message("|!challenge-mdp-1", afficher_message=False)
        elif msg_a_envoyer == "!utilisateurs":  # Liste des utilisateurs.
            if not arguments.serveur:  # Si c'est un client, demander la liste au serveur.
                envoi_message("!client-utilisateurs", afficher_message=False)
            else:  # Sinon, affiche la liste.
                liste_utilisateurs = ""
                for data_co in data_connexions_list:
                    liste_utilisateurs += f"\n            {data_co[1]} {data_co[2]} ({data_co[4]})"
                liste_utilisateurs = ''.join((f"!utilisateurs >\n   Serveur: {hote} {arguments.nom} (Vous)\n   Clients:",
                                              liste_utilisateurs[12:]))
                afficher(liste_utilisateurs)
        elif msg_a_envoyer in ["!help", "!aide", "!aled"]:  # Commande d'aide.
            afficher(f"{msg_a_envoyer} >\n   !quitter / Ctrl+C   Fermer la connexion"
                     "\n   !cls                Supprimer les messages affichés"
                     "\n   !fichier FICHIER    Envoyer un fichier"
                     "\n   !utilisateurs       Afficher la liste des utilisateurs connectés"
                     "\n   !motdepasse         Vérifier l'authenticité du serveur", notification=False)
        else:  # Message normal.
            envoi_message(msg_a_envoyer, afficher_message=False)  # Chiffrement et envoi du message.
            if not arguments.dev:
                afficher(msg_a_envoyer, notification=False)


def envoi_message(message, co_reception=None, co_unique=None, afficher_message=True):
    """ Envoi d'un message chiffré au(x) client(s). """

    if afficher_message and (not arguments.dev or message.startswith("<système>")):
        afficher(message, notification=False)
    for data_co in data_connexions_list:
        if (not co_unique and data_co[0] != co_reception) or data_co[0] == co_unique:
            objet_chiffrement = AES.new(data_co[3], AES.MODE_OCB)
            texte_chiffre, tag = objet_chiffrement.encrypt_and_digest(message.encode())
            message_chiffre = (f"{base64.b64encode(objet_chiffrement.nonce).decode()}"
                               f"{base64.b64encode(tag).decode()}"
                               f"{base64.b64encode(texte_chiffre).decode()}")
            data_co[0].sendall(message_chiffre.encode())  # Envoi du message chiffré.
            if arguments.dev:  # Mode développeur.
                afficher(f"[dev] {message} ({message_chiffre}) >> {data_co[1]}",
                         notification=False)


def envoi_fichier(nom_fichier, taille_fichier, co_reception=None, afficher_message=True):
    """ Chiffrement et envoi d'un fichier. """

    with open(nom_fichier, "rb") as f:  # Lecture du fichier à envoyer.
        contenu_fichier = f.read()
    for data_co in data_connexions_list:  # Envois du fichier à chaque connexion.
        if data_co[0] != co_reception:
            print("Chiffrement...")
            # Création de la barre de progression de l'envois du fichier.
            barre_progression = tqdm.tqdm(range(taille_fichier), "Envoi fichier", unit="o", unit_scale=True)
            objet_chiffrement = AES.new(data_co[3], AES.MODE_OCB)  # Chiffrement du fichier avec la clé de la connexion.
            fichier_chiffre, tag = objet_chiffrement.encrypt_and_digest(contenu_fichier)
            donnees_chiffre = objet_chiffrement.nonce + tag + fichier_chiffre
            # Envois du message de signalement d'envois d'un fichier avec le nom et la taille du fichier.
            envoi_message(f"|!f{os.path.basename(nom_fichier)}|{taille_fichier}",
                          co_unique=data_co[0], afficher_message=False)
            afficher(notification=False)
            print(f"<système> En attente de réponse de {data_co[1]}...")
            xp = 0
            while True:  # Envois du fichier sous forme de paquets d'une longueur de LEN_BUFFER_TCP.
                if (xp*LEN_BUFFER_TCP)+LEN_BUFFER_TCP > len(donnees_chiffre):
                    # Il ne reste plus assez de données à envoyer pour envoyer un paquet complet.
                    data_co[0].sendall(donnees_chiffre[xp*LEN_BUFFER_TCP:])
                    break
                else:  # Paquet complet.
                    data_co[0].sendall(donnees_chiffre[xp * LEN_BUFFER_TCP:(xp * LEN_BUFFER_TCP) + LEN_BUFFER_TCP])
                barre_progression.update(LEN_BUFFER_TCP)
                xp += 1
            data_co[0].sendall(b"|!f|")  # Signalement de la fin des envois de paquets du fichier.
            barre_progression.close()
            afficher(notification=False)
    if afficher_message:
        afficher(f"[Fichier {nom_fichier} - {taille_fichier}o]", notification=False)


def ferme_connexion(data_co=None, message_client=None):
    """ Ferme la connexion. """

    global data_connexions_list
    global quitter
    global message_input

    if not quitter:
        if not data_co or not arguments.serveur:  # Déconnexion totale et fermeture du programme.
            quitter = True
            if message_annulation:
                print("\n<système> Annulation.")
            else:
                afficher(message_client, notification=False)
            for data_co in data_connexions_list:  # Fermeture de chaque connexion.
                try:
                    data_co[0].shutdown(socket.SHUT_WR)
                except OSError:  # La connexion est deja fermée.
                    pass
            data_connexions_list = []
            exit(0)
        else:  # déconnexion d'un seul client.
            data_co[0].close()
            try:
                if data_co[2]:
                    nom_client = f" ({data_co[2]})"
                else:
                    nom_client = ""
                # Supprimer la connexion de la liste des connexions actives puis afficher et partager l'annonce.
                data_connexions_list = [coliste for coliste in data_connexions_list if data_co is not coliste]
                message_input = ""
                #afficher(f"<système> Le client {data_co[1]}{nom_client} s'est déconnecté.")
                envoi_message(f"<système> Le client {data_co[1]}{nom_client} s'est déconnecté.")
                if not data_connexions_list:
                    print("\nEn attente de client...  ctrl+c pour quitter")
            except Exception:
               pass


def afficher(nouvel_element=None, notification=True):
    """ Afficher un élément à l'écran.

        nouvel_element : Nouvel élément à afficher.
                         Si None, rafraîchit juste l'écran."""

    global liste_ecran
    global message_input

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
    for element in liste_ecran:  # Afficher chaque élément.
        print(element)
    if message_input:  # Consigne pour l'input, toujours l'afficher tout en bas.
        print(message_input)


def signal_handler(signal, frame):
    """ Gestion du ctrl+c: ferme la connexion. """

    if arguments.serveur:  # Signalement de la déconnexion aux clients.
        envoi_message("|!serveur-fermeture", afficher_message=False)
        ferme_connexion(message_client="\n<système> ctrl+c détecté: Déconnexion. ENTRÉE pour fermer.")
    else:  # Signalement de la déconnexion au serveur.
        envoi_message("|!client-fermeture", afficher_message=False)
        ferme_connexion(message_client="\n<système> ctrl+c détecté: Déconnexion et fermeture.")


signal(SIGINT, signal_handler)  # Gestion du ctrl+c.
# Définition des arguments de la commande.
argumentParser = argparse.ArgumentParser(description="USI: Communications simples et chiffrées."
                                                     " github.com/Robin-mlh/USI\nUne fois connecté, "
                                                     "entrez '!aide' pour voir les commandes disponibles.",
                                         usage="usi.py [-dhn] { -s | -c [HOTE[:PORT]] } [-p PORT] [-k CLE] [-m NOM]",
                                         formatter_class=argparse.RawTextHelpFormatter, add_help=False)
argumentParser._optionals.title = 'Options'
group = argumentParser.add_mutually_exclusive_group(required=True)
group.add_argument('-s', "--serveur", action='store_true',
                   help="Utiliser le mode serveur pour attendre des clients")
group.add_argument('-c', "--client", metavar="HOTE[:PORT]", nargs="?", default=False,
                   help="Utiliser le mode client pour se connecter à un serveur\n"
                        "Spécifier l'adresse du serveur (par défaut: localhost)\n"
                        "Exemples: -c 108.177.16.0, -c example.com:45800")
argumentParser.add_argument("-m", "--nom", metavar="NOM",
                            help="Spécifier un nom à utiliser")
argumentParser.add_argument("-p", "--port", type=int, default=12800, metavar="PORT",
                            help="Spécifier le port à utiliser (par defaut: 12800)")
argumentParser.add_argument("-k", "--cle", type=str, metavar="CLE",
                            help="Spécifier une clé de session de 128, 192 ou 256 bits\n"
                                 "La clé doit être encodée en base64 ou en hexadecimal")
argumentParser.add_argument("-n", "--notifications", action="store_true", help="Activer les notifications")
argumentParser.add_argument("-d", "--dev", action="store_true",
                            help="Mode pour afficher plus d'informations techniques")
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
if not arguments.nom:
    arguments.nom, nom_affiche = "", ""
else:
    if len(arguments.nom) >= 12:
        arguments.nom = arguments.nom[:12]  # 12 caractères maximum pour le nom affiché.
    nom_affiche = f"Votre nom affiché: {arguments.nom}"

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
    afficher(f"Adresse ip locale: {ip_locale}   {ip_publique}"
             f"   Port écouté: {arguments.port}   {nom_affiche}\n", notification=False)
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
            cle_privee = RSA.generate(CLE_RSA_BITS)  # Génération de la clé privée RSA.
            cle_publique = cle_privee.public_key()  # Obtention de la clé publique avec la clé privée.
            try:  # Partager la clé publique au client et attendre sa clé publique ainsi que la clé de session.
                connexion.sendall(base64.b64encode(cle_publique.export_key("DER")))
                message_recu = connexion.recv(LEN_BUFFER_TCP)
                cle_publique_client = RSA.import_key(base64.b64decode(message_recu[:392]))
                cle_session = PKCS1_OAEP.new(cle_privee).decrypt(base64.b64decode(message_recu[736:]))
            except (ValueError, ConnectionResetError):  # Le client a annulé la connexion.
                ferme_connexion([connexion, infos_connexion[0], ""])
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
                ferme_connexion([connexion, infos_connexion[0], ""])
                continue
            # Génération de l'empreinte SHA256 de vérification de l'authenticité de la connexion.
            empreinte_verif = SHA256.new(cle_publique_client.export_key("DER") +
                                         cle_publique.export_key("DER")).hexdigest()
        else:
            empreinte_verif = SHA256.new(cle_session).hexdigest()
        # Ajout de la connexion et des informations associées à la liste des connexions actives.
        data_connexions_list.append([connexion, infos_connexion[0], "", cle_session, empreinte_verif])
        # Réception du nom du nouveau client et envoi du nom du serveur.
        message_recu_brut = connexion.recv(LEN_BUFFER_TCP).decode()
        objet_dechiffrement = AES.new(cle_session, AES.MODE_OCB, nonce=base64.b64decode(message_recu_brut[:20]))
        try:
            message_recu = objet_dechiffrement.decrypt_and_verify(base64.b64decode(message_recu_brut[44:]),
                                                                  base64.b64decode(message_recu_brut[20:44])).decode()
        except ValueError as e:
            message_recu = ""
            afficher(f"[Impossible de déchiffrer le nom du nouveau client: {e}]")
        data_connexions_list[-1][2] = message_recu[9:-1]
        envoi_message(f"|!pseudo={arguments.nom}|", co_unique=connexion, afficher_message=False)
        # Thread de réception pour chaque client.
        threading.Thread(target=reception, args=[data_connexions_list[-1]]).start()
        if not thread_envoi_lance:  # Lance l'unique thread d'envoi de message (et de commande).
            threading.Thread(target=thread_envoi).start()
            thread_envoi_lance = True
        nom_nouveau_client = data_connexions_list[-1][2]
        if nom_nouveau_client:
            nom_nouveau_client = f" ({data_connexions_list[-1][2]})"
        envoi_message(f"<système> Le client {infos_connexion[0]}{nom_nouveau_client} c'est connecté."
                      f"\nEmpreinte de vérification: {empreinte_verif}", co_reception=connexion)

else:  # Client.
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
        cle_privee = RSA.generate(CLE_RSA_BITS)  # Génération de la clé RSA.
        cle_publique = cle_privee.public_key()  # Génération de la clé publique avec la clé privée.
        cle_session = Random.get_random_bytes(CLE_SESSION)  # Génération de la clé de session.
        try:  # Reception de la clé publique du serveur.
            cle_publique_serveur = RSA.import_key(base64.b64decode(connexion.recv(LEN_BUFFER_TCP)))
        except (ConnectionResetError, ValueError):
            raise SystemExit("<système> Le serveur a fermé la connexion.")
        afficher(f"\n[dev] Clé publique: {cle_publique.export_key('PEM')}"
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
        empreintes_verif = SHA256.new(cle_publique.export_key("DER") +
                                      cle_publique_serveur.export_key("DER")).hexdigest()
    else:
        empreintes_verif = SHA256.new(cle_session).hexdigest()
    # Ajout de la connexion avec le serveur et des informations associées à la liste des connexions actives.
    data_connexions_list.append([connexion, hote, "", cle_session, empreintes_verif])
    # Envoi du nom du serveur et réception du nom du client.
    envoi_message(f"|!pseudo={arguments.nom}|", afficher_message=False)
    message_recu_brut = connexion.recv(LEN_BUFFER_TCP).decode()
    objet_dechiffrement = AES.new(cle_session, AES.MODE_OCB, nonce=base64.b64decode(message_recu_brut[:20]))
    try:
        message_recu = objet_dechiffrement.decrypt_and_verify(base64.b64decode(message_recu_brut[44:]),
                                                              base64.b64decode(message_recu_brut[20:44])).decode()
    except ValueError as e:
        message_recu = ""
        afficher(f"[Impossible de déchiffrer le nom du nouveau client: {e}]")
    data_connexions_list[-1][2] = message_recu[9:-1]
    if not arguments.dev:
        liste_ecran = []  # Réinitialise l'écran.
    nom_serveur = data_connexions_list[-1][2]
    if nom_serveur:
        nom_serveur = f" ({data_connexions_list[-1][2]})"
    afficher(f"Connexion sécurisée établie avec le serveur {hote}:{arguments.port}{nom_serveur}"
             f"   {nom_affiche}\nEmpreinte de vérification: {empreintes_verif}\n",
             notification=False)
    # Lance l'unique thread de réception des messages du serveur.
    threading.Thread(target=reception, args=[data_connexions_list[-1]]).start()
    thread_envoi()  # Execute la fonction (boucle) d'envoi des messages et commandes.
