# DNS cache poisoning

## About

`DNS cache poisoning` / `DNS spoofing` attack based on `DNSpooq` (2021).

[Original research](https://www.jsof-tech.com/wp-content/uploads/2021/01/DNSpooq-Technical-WP.pdf),
[PoC](https://github.com/knqyf263/dnspooq)

Master's thesis on the topic: `Methods of Protection Against DNS Cache Poisoning`, PTI KPI, 2024.

## Usage

1. Navigate to project root and then:

### Automatic Installation

Run the PowerShell script:

```ps
./tab.ps1
```

### Manual Installation

Execute the following commands:

```ps
docker-compose down --timeout 0 --rmi local
docker-compose up --build -d
docker-compose exec attacker bash
```

2. Start the attack by running:

```bash
python attacker.py
```



