<?php

/**
 * Base presenter for all application presenters.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
abstract class BasePresenter extends Presenter
{

    /** @var Data model */
    protected $model;

    /** @persistent  */
    public $profile = HSConnection::ALL;

    /** @var All available profiles */
    protected $profiles;
    /** @var Formats from config */
    protected $formats;
    /** @var Data from configuration file */
    protected $config;

    /** Begin of application life cycle */
    public function startup() {


        $this->config = ArrayHash::from( $this->context->parameters );
        $this->model = new Model( $this->context->getService('conn') );
        $this->formats = ArrayHash::from( $this->context->parameters['formats'] );

        try {
            $this->profiles = $this->model->getProfiles();
        } catch(HSCException $e) {}

        parent::startup();
    }


    /**
     * Generate profiles form
     * @return AppForm
     */
    public function createComponentFrmProfile() {
        $frm = new AppForm();
        $frm->addSelect("profile", "Změnit profil", $this->profiles)
            ->setDefaultValue($this->profile);
        $frm->addSubmit("send","Odeslat");
        $frm->onSuccess[] = array($this, 'frmProfileSuccess');
        return $frm;
    }

    /**
     * Callback on success profiles form
     * @param Form $frm
     */
    public function frmProfileSuccess(Form $frm) {
        $this->profile = $frm->values->profile;
        if(!$this->isAjax())
            $this->redirect('this');
    }

    /**
     * Prepare template before rendering
     */
    public function beforeRender() {
        $this->template->formats = $this->formats;
        $this->template->config = $this->config;
        $this->template->registerHelper('syntax', array($this,'helperGeSHi'));

        $this->payload->link = $this->link('this');
    }

    /**
     * Create helper to GeSHi syntax highlighter
     * @param string $s
     * @param string $lang
     * @return mixed
     */
    public function helperGeSHi($s, $lang = 'whois') {
        $geshi = new GeSHi($s, $lang);
        return  $geshi->parse_code();
    }
    
}
