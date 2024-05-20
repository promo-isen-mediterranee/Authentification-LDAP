import { Component, OnInit } from '@angular/core';
import {FormBuilder, FormGroup, ReactiveFormsModule, Validators} from '@angular/forms';
import { tap } from 'rxjs/operators';
import {HttpClient, HttpClientModule, HttpHeaders} from '@angular/common/http';
import {Router} from "@angular/router";

interface Credentials {
  username: string;
  password: string;
}

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    ReactiveFormsModule,
    HttpClientModule
  ],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginForm!: FormGroup;

  constructor(private formBuilder: FormBuilder, private http: HttpClient, private router: Router) { }

  ngOnInit() {
    this.loginForm = this.formBuilder.group({
      username: ['', Validators.required],
      password: ['', Validators.required]
    });
  }

  onSubmit() {
    if (this.loginForm.invalid) {
      return;
    }

    const credentials: Credentials = this.loginForm.value;
    const body = new URLSearchParams();
    body.set('username', credentials.username);
    body.set('password', credentials.password);
    const headers = new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' });
    this.http.post('http://localhost:5050/auth/login', body.toString(), { observe: 'response', withCredentials: true, headers: headers }).pipe(
      tap(response => {
        if (response.status === 200) {
          this.router.navigate(['/home']).then(r => {});
        }
      })
    ).subscribe();
  }
}
