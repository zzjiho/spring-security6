package com.eazybytes.controller;

import com.eazybytes.model.Contact;
import com.eazybytes.repository.ContactRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@RestController
@RequiredArgsConstructor
public class ContactController {

    private final ContactRepository contactRepository;

    /**
     * @PreFilter:
     * 데이터가 비즈니스 로직(DB 저장 등)에 들어가기 전에 원천적으로 차단
     *
     * @PostFilter:
     * 비즈니스 로직(DB 저장)은 그대로
     * 실행되지만, 최종적으로 클라이언트에게 반환하는
     * 결과에서만 특정 데이터를 숨깁
     */

    @PostMapping("/contact")
    // @PreFilter("filterObject.contactName != 'Test'")
    @PostFilter("filterObject.contactName != 'Test'")
    public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
        List<Contact> returnContacts = new ArrayList<>();
        if(!contacts.isEmpty()) {
            Contact contact = contacts.getFirst();
            contact.setContactId(getServiceReqNumber());
            contact.setCreateDt(new Date(System.currentTimeMillis()));
            Contact savedContact = contactRepository.save(contact);
            returnContacts.add(savedContact);
        }
        return returnContacts;
    }

    public String getServiceReqNumber() {
        Random random = new Random();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
