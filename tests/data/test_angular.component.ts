import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-user-profile',
  template: `
    <div [innerHTML]="userBio"></div>
  `
})
export class UserProfileComponent {
  userBio: any;
  
  constructor(private sanitizer: DomSanitizer) {}
  
  // Security issue: Bypassing sanitization for user input
  updateBio(bio: string) {
    this.userBio = this.sanitizer.bypassSecurityTrustHtml(bio);
  }
  
  // Security issue: Hardcoded API key
  private apiKey = 'sk-1234567890abcdef';
  
  // Security issue: Using HTTP instead of HTTPS
  apiUrl = 'http://api.example.com/users';
}
