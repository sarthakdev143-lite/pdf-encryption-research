# Authentication matrix

- files: 33   engines: 6   probes: 1386
- **AUTH-BYPASS: 0**   FAIL-CONTROL: 3

## FAIL-CONTROL (correct password rejected / no content)

- corpus/writers/reportlab_s256.pdf | pypdf | ValueError: Invalid key size (384) for AES.
- corpus/writers/reportlab_s256.pdf | pdfminer | PdfminerException: Invalid key size (384) for AES.
- corpus/writers/reportlab_s256.pdf | pymupdf | FileDataError: Failed to open file 'D:\\Sarthak\\Coding\\Work\\KWTC\\NavinData\\Systango\\pdf-encryption-research\\corpus\\writers\\reportlab_s256.pdf'.

## Summary by verdict

- ACCEPTED-CONTROL: 195
- ACCEPTED-OWNER: 195
- ERROR: 1
- FAIL-CONTROL: 3
- REJECTED: 992