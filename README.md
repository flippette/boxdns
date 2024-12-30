# boxdns

Dynamic DNS client for Mail-in-a-Box.

## Usage

```sh
boxdns -c boxdns.conf
```

## Configuration

`boxdns.conf` is a JSON file with the following schema:

```json
{
  "hostname": "box.example.com",
  "domain": "mydomain.example.com",
  "email": "john.doe@example.com",
  "password": "password123",
  "secret": "amFuIFBpbg==",
  "cooldown": "5m"
}
```

- `hostname`: The hostname of your Box.
- `domain`: The DDNS domain you want to set.
- `email`: The email of an administrative user.
- `password`: The password of that user.
- `secret` (optional): The TOTP token for the admin panel.
- `cooldown`: The cooldown in between updates, accepted by [humantime-serde](https://docs.rs/humantime-serde)
