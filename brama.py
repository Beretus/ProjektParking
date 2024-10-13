import cv2
from pyzbar.pyzbar import decode
from datetime import datetime
import time
import RPi.GPIO as GPIO
import requests
from picamera2 import Picamera2

# Konfiguracja serwomotora
SERVO_PIN = 18
PWM_FREQ = 50  # Częstotliwość sygnału PWM w hercach
OPEN_ANGLE = 7.5  # Kąt otwarcia serwomotora (wartość PWM)

# Inicjalizacja GPIO
GPIO.setmode(GPIO.BCM)
GPIO.setup(SERVO_PIN, GPIO.OUT)
GPIO.setwarnings(False)
servo = GPIO.PWM(SERVO_PIN, PWM_FREQ)
servo.start(0)

# Inicjalizacja kamery Picamera2
cam = Picamera2()
height = 480
width = 640
cam.configure(cam.create_video_configuration(main={"format": 'RGB888', "size": (width, height)}))
cam.start()

# Adres serwera Flask
SERVER_URL = 'http://192.168.4.103:5000/qr_scan'

while True:
    # Przechwytywanie obrazu z kamery
    frame = cam.capture_array()
    
    # Dekodowanie kodów QR
    decoded_objects = decode(frame)
    
    # Wyświetlanie obrazu z kamery
    cv2.imshow('frame', frame)
    
    # Sprawdzanie, czy zdekodowano jakieś kody QR
    if decoded_objects:
        for obj in decoded_objects:
            qr_data = obj.data.decode('utf-8')
            print('Data:', qr_data)
            
            # Wysłanie danych QR do serwera Flask
            response = requests.post(SERVER_URL, json={'qr_data': qr_data})
            print(response.text)  # Dodaj to, aby zobaczyć, co zwraca serwer
            
            try:
                result = response.json()
                if 'error' in result:
                    print('Error:', result['error'])
                else:
                    print('Message:', result['message'])
                    
                    # Otwarcie bramy serwomotorem
                    servo.ChangeDutyCycle(OPEN_ANGLE)
                    time.sleep(3)  # Otwarcie na 3 sekundy
                    
                    # Zamknięcie bramy serwomotorem
                    servo.ChangeDutyCycle(0)
            except ValueError:
                print("Response content is not valid JSON")
    
    # Przerwanie pętli po naciśnięciu klawisza 'q'
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

# Zwalnianie zasobów kamery, zamykanie okien i zatrzymywanie serwomotora
cv2.destroyAllWindows()
servo.stop()
GPIO.cleanup()

