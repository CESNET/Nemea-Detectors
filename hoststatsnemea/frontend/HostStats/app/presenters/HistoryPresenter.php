<?php

/**
 * History presenter.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class HistoryPresenter extends BasePresenter
{

    /** @persistent */
    public $from;
    /** @persistent */
    public $to;
    /** @persistent */
    public $ip;

    public $window;

    /**
     * prepare parameters in Default action
     * @param string|null $ip
     */
    public function actionDefault($ip=null) {

        $from = new Timeslot($this->from ? $this->from : '- 1 hour');
        $to = new Timeslot($this->to ? $this->to : null);

        try {
            $this->window = new Timewindow($from, $to);
        } catch(TimewindowException $e) {
            $from = new Timeslot('- 1 hour');
            $to = new Timeslot(null);
            $this->window = new Timewindow($from, $to);
            $this->flashMessage($e->getMessage(), 'error');
        }

    }

    /**
     * prepare Default view
     * @param string|null $ip
     */
    public function renderDefault($ip=null)
	{
        $this->template->ip = $this->ip;
        $this->template->timewindow = $this->window;


        // Když je zadaná IP získáme data
        if($this->ip) {
            try{
                // IP oveříme hned at to nemusí dělat server
                if(!Nettools::isIP($this->ip))
                    throw new HSCBadCommandException("'{$this->ip}' is not valid IP address");

                $list = $this->model->getHostHistory( $this->ip, $this->profile, $this->window->from, $this->window->to );
                $this->template->list = $list;
                $this->template->chartHistoryIp = $this->_getListForChart( $list );

            } catch(HSCBadCommandException $e) {
                $this->flashMessage($e->getMessage(), "error");
            }
        }

        $this['frmTimewindow']->setDefaults(array(
            'from' => $this->window->from->format( $this->formats->timeslot ),
            'to' => $this->window->to->format( $this->formats->timeslot )
        ));


        if($this->isAjax())
            $this->invalidateControl();
	}

    /**
     * Convert list to json for charts
     * @param array $list
     * @return string JSON
     */
    protected function _getListForChart( $list ) {
        $result = array();
        foreach($list as $item)
            $result[$item->timeslot->getTimestamp()] = $item;
        return Json::encode($result);
    }

    /**
     * Do signal windowPrev!
     */
    public function handleWindowPrev() {
        // Posuneme okno
        $this->window->prev();
        // Aktualizujeme persistentní parametry;
        $this->from = $this->window->from->getName();
        $this->to = $this->window->to->getName();

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }
    /**
     * Do signal windowNext!
     */
    public function handleWindowNext() {
        // Posuneme okno
        $this->window->next();
        // Aktualizujeme persistentní parametry;
        $this->from = $this->window->from->getName();
        $this->to = $this->window->to->getName();

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }
    /**
     * Do signal windowSet!
     */
    public function handleWindowSet($from=null,$to=null) {

        try {
            $this->window = new Timewindow(new Timeslot($from), new Timeslot($to));
        } catch(TimewindowException $e) {
            $this->flashMessage($e->getMessage(), 'error');
        }
        // Aktualizujeme persistentní parametry;
        $this->from = $this->window->from->getName();
        $this->to = $this->window->to->getName();

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }


    /**
     * Create IP address form
     * @return AppForm
     */
    public function createComponentFrmIpAddress() {
        $frm = new AppForm();
        $frm->addText('ip','IP address')
            ->setDefaultValue($this->ip)
            ->setHtmlID('ipaddress');
        $frm->addSubmit('send','Send');
        $frm->onSuccess[] = array($this,'frmIpAddressSuccess');
        return $frm;
    }

    /**
     * Callbeck on success IP address form
     * @param Form $frm
     */
    public function frmIpAddressSuccess(Form $frm) {
        $this->ip = $frm->values->ip;

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }

    /**
     * Create timewindow form
     * @return AppForm
     */
    public function createComponentFrmTimewindow() {
        $frm = new AppForm();
        $frm->addText('from','From');
        $frm->addText('to','To');
        $frm->addSubmit('send','Submit');
        $frm->onSuccess[] = array($this,'frmTimewindowSuccess');
        return $frm;
    }

    /**
     * Callbeck on success timewindow from
     * @param Form $frm
     */
    public function frmTimewindowSuccess(Form $frm) {

        $from = $frm->values->from;
        $to = $frm->values->to;

        try {
            $this->window = new Timewindow(new Timeslot($from), new Timeslot($to));
        } catch(TimewindowException $e) {
            $this->flashMessage($e->getMessage(), 'error');
        }

        // Actuliye persistent params
        $this->from = $this->window->from->getName();
        $this->to = $this->window->to->getName();

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }

    /**
     * Prepare Whois view
     * @param $ip
     */
    public function renderWhois($ip) {

        $host = !empty($this->context->parameters['nettools']['whois']['host']) ? $this->context->parameters['nettools']['whois']['host'] : null;
        $this->template->whois = $ip ? Nettools::whois($this->ip, $host) : null;
    }



}
