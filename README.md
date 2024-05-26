# How to make everything work together

## 1 - Execute in a cli

```shell
docker compose --build -d
```

## 2 - Launch the angular app for testing the login

```shell
cd API_Auth-Test
npm run start
```

### Troubleshooting for ng command not found
Execute this command in the terminal, still in the API_Auth-Test folder
```shell
npm install @angular/cli
```
then you can run the command to start the angular app.