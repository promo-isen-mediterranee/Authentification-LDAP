import {Component} from '@angular/core';
import {Router} from '@angular/router';
import {HttpClient, HttpClientModule} from "@angular/common/http";
import {tap} from "rxjs/operators";

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [
    HttpClientModule
  ],
  templateUrl: './home.component.html'
})
export class HomeComponent {
  constructor(private router: Router, private http: HttpClient) {
  }

  logout() {
    this.http.post('http://localhost:5050/auth/logout', {}, {observe: 'response', withCredentials: true}).pipe(
      tap(response => {
        if (response.status === 200) {
          this.router.navigate(['/login']).then(r => {});
        }
      })
    ).subscribe();
  }

  getAllUsers() {
    this.http.get('http://localhost:5050/auth/getAllUsers', {observe: 'response', withCredentials: true}).pipe(
      tap(response => {
        if (response.status === 200) {
          console.log(response.body);
        }
      })
    ).subscribe();
  }
}
