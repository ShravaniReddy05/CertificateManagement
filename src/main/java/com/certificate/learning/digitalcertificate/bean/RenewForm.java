package com.certificate.learning.digitalcertificate.bean;


public class RenewForm {

    private String alias;
    private int renewYears;

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public int getRenewYears() {
        return renewYears;
    }

    public void setRenewYears(int renewYears) {
        this.renewYears = renewYears;
    }
}