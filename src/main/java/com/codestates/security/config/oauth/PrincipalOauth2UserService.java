package com.codestates.security.config.oauth;

import com.codestates.security.auth.PrincipalDetails;
import com.codestates.security.config.oauth.provider.GoogleUserInfo;
import com.codestates.security.config.oauth.provider.NaverUserInfo;
import com.codestates.security.config.oauth.provider.OAuth2UserInfo;
import com.codestates.security.model.Member;
import com.codestates.security.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private MemberRepository memberRepository;

    //메서드가 종료되면 @AuthenticationPrincipal 애너테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

//        System.out.println("userRequest : " + userRequest);
//        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());
//        System.out.println("getTokenValue = " + userRequest.getAccessToken().getTokenValue());
        System.out.println("getAttributes = " + super.loadUser(userRequest).getAttributes());


        OAuth2UserInfo oAuth2UserInfo = null;
        OAuth2User oAuth2User = super.loadUser(userRequest);

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            Map response = (Map) oAuth2User.getAttributes().get("response");
            oAuth2UserInfo = new NaverUserInfo(response);
        }




        String provider = oAuth2UserInfo.getProvider(); //google
        String providerId = oAuth2UserInfo.getProviderId();
//        String username = oAuth2User.getAttribute("name");
        //위와 같이 username을 설정하게 되면 중복될 가능성 존쟤(동명이인)
        String username = provider + "_" + providerId;
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        Member member = memberRepository.findByUsername(username);

        //처음 로그인한 유저 => 회원가입 처리
        if (member == null) {
            member = Member.builder()
                    .username(username)
                    .email(email)
                    .provider(provider)
                    .providerId(providerId)
                    .role(role)
                    .build();
            memberRepository.save(member);
        }
        System.out.println(member);


        return new PrincipalDetails(member, oAuth2User.getAttributes());
    }
}
