<?php

/**
 * Details presenter.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class DetailsPresenter extends BasePresenter
{

    /** @persistent */
    public $timeslot;

    /** @persistent */
    public $filter;

    /** @persistent */
    public $limit = 20;

    /** @persistent */
    public $sort = null;

    /** @persistent */
    public $asc = false;

    /**
     * prepare Default view
     * @param null|string $timeslot
     */
    public function renderDefault($timeslot = null)
	{
        if($timeslot)
            $timeslot = new Timeslot($timeslot);
        try {
            if(!$timeslot)
                $timeslot = $this->model->getStatus()->timeslot;
        } catch (HSCException $e) {}
        if(!$timeslot)
            $timeslot = new Timeslot(); // Aktualni

        $this->template->timeslot = $timeslot;

        $this->template->sort = $this->sort;
        $this->template->asc = $this->asc;

        // set default value to form
        $this['frmTimestamp']['timeslot']->setDefaultValue( $timeslot->format( $this->formats->timeslot ) );

        try {
		    $this->template->list = $this->model->getTimeslotData($timeslot, $this->profile, $this->filter, $this->limit, $this->sort, (int) $this->asc);
        } catch(HSCException $e) {
            $this->flashMessage( $e->getMessage(), 'error' );
        }

        if($this->isAjax)
            $this->invalidateControl();
	}


    /**
     * Create filter form
     * @return AppForm
     */
    public function createComponentFrmFilter() {
        $frm = new AppForm();
        $frm->addText('filter','Filter')
            ->setDefaultValue($this->filter)
            ->setHtmlID('filter');
        $frm->addSubmit('send','Send');
        $frm->onSuccess[] = array($this,'frmFilterSuccess');
        return $frm;
    }

    /**
     * Callback on success filter form
     * @param Form $frm
     */
    public function frmFilterSuccess(Form $frm) {
        $this->filter = $frm->values->filter;

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }

    /**
     * Create timestamp form
     * @return AppForm
     */
    public function createComponentFrmTimestamp() {
        $frm = new AppForm();
        $frm->addText('timeslot','Timeslot')
            ->setDefaultValue($this->timeslot);
        $frm->addSubmit('send','Submit');
        $frm->onSuccess[] = array($this,'frmTimestampSuccess');
        return $frm;
    }

    /**
     * Callback on success timestamp form
     * @param Form $frm
     */
    public function frmTimestampSuccess(Form $frm) {
        $this->timeslot = $frm->values->timeslot;

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }

    /**
     * Create limit form
     * @return AppForm
     */
    public function createComponentFrmLimit() {
        $frm = new AppForm();
        $frm->addText('limit','Number of results')
            ->setDefaultValue($this->limit)
            ->setType('number')
            ->addRule($frm::INTEGER,"%label musí být celé číslo");
        $frm->addSubmit('send','Send');
        $frm->onSuccess[] = array($this,'frmLimitSuccess');
        return $frm;
    }

    /**
     * Callback on success limit form
     * @param Form $frm
     */
    public function frmLimitSuccess(Form $frm) {
        $this->limit = (int) $frm->values->limit ?: $this->limit;

        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }


}
