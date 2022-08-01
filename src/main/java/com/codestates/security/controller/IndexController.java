package com.codestates.security.controller;

import com.codestates.security.auth.PrincipalDetails;
import com.codestates.security.model.Member;
import com.codestates.security.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    MemberRepository memberRepository;

    @GetMapping("/")
    public String index(@AuthenticationPrincipal PrincipalDetails principalDetails, Model model) {
        try {
            if (principalDetails.getUsername() != null) {
                model.addAttribute("username", principalDetails.getUsername());
            }
        } catch (NullPointerException e) {
            return "index";
        }
        return "index";
    }

    //구글, 일반 로그인 모두 처리 가능
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println(principalDetails.getMember());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/login")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/join")
    public String join() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(Member member) {
        member.setRole("ROLE_USER");
        String rawPassword = member.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        member.setPassword(encPassword);

        memberRepository.save(member);

        return "redirect:/login";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "info";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "data";
    }


    //일반 로그인 -> PrincipalDetails
    @GetMapping("/loginTest")
    public @ResponseBody String loginTest(Authentication authentication) {
        System.out.println("============/loginTest==========");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal.getMember() = " + principalDetails.getMember());
        return "세션 정보 확인";
    }
    //애너테이션을 사용하여 위의 메서드 변환
    @GetMapping("/loginTest2")
    public @ResponseBody String loginTest2(@AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("============/loginTest==========");
        System.out.println("principal.getMember() = " + userDetails.getUsername());
        return "세션 정보 확인2";
    }

    //OAuth 로그인 -> OAuth2User
    @GetMapping("/loginTest3")
    public @ResponseBody String loginTest3(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth2User) {
        System.out.println("============/loginTest3==========");
        OAuth2User oauth = (OAuth2User) authentication.getPrincipal();
        System.out.println("oauth.getAttributes() = " + oauth.getAttributes());
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());
        return "세션 정보 확인3";
    }

}