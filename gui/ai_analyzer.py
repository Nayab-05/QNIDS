import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq

# .env load karo project root se (gui/ ke ek folder upar)
# D:\QNIDS-Project\.env
load_dotenv(Path(__file__).parent.parent / '.env')


class AIAnalyzer:

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")

        # Agar .env mein key nahi mili toh clearly batao
        if not self.api_key:
            raise ValueError(
                "GROQ_API_KEY not found.\n"
                "Check karo: D:\\QNIDS-Project\\.env file exist karti hai?\n"
                "Aur usme GROQ_API_KEY=gsk_... likha hai?"
            )

        self.client = Groq(api_key=self.api_key)

    def analyze(self, attack_info, ip,
                confidence=0, protocol="TCP",
                src_bytes=0, duration=0,
                count=0, serror_rate=0,
                callback=None):
        """
        Background thread mein Groq API call karta hai.
        Callback function result ke saath call hota hai jab response aata hai.
        """
        thread = threading.Thread(
            target=self._call_api,
            args=(
                attack_info, ip,
                confidence, protocol,
                src_bytes, duration,
                count, serror_rate,
                callback
            ),
            daemon=True
        )
        thread.start()

    def _call_api(self, attack_info, ip,
                  confidence, protocol,
                  src_bytes, duration,
                  count, serror_rate,
                  callback):
        """
        Actual Groq API call — background thread mein chalta hai.
        GUI freeze nahi hoti.
        """
        try:
            prompt = f"""You are a cybersecurity expert analyzing suspicious \
network traffic detected by QNIDS (Quantum-Inspired Network Intrusion \
Detection System).

Suspicious traffic details:
- Source IP:       {ip}
- Pattern:         {attack_info}
- Protocol:        {protocol}
- Confidence:      {confidence}%
- Source bytes:    {src_bytes}
- Duration:        {duration}s
- Connection count:{count}
- Error rate:      {serror_rate}

This was flagged as anomalous by the Isolation Forest anomaly detector.

In exactly 4 short lines explain:
1. What attack type this could be
2. Why it is suspicious
3. Potential impact
4. Recommended action

Be concise and technical."""

            response = self.client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )

            result = response.choices[0].message.content

            if callback:
                callback(result)

        except Exception as e:
            error_msg = f"AI Analysis error: {str(e)}"
            print(error_msg)
            if callback:
                callback(error_msg)