<?php

/**
 * Detectors presenter.
 * @author Petr Sládek <xslade12@stud.fit.vutbr.cz>
 * @package HostStats\Frontend
 */
class DetectorsPresenter extends BasePresenter
{

    /** @persistent */
    public $date;

    /** @var days in which they were detected attacks */
    public $dates;

    /**
     * prepare Default view
     * @param string|null $date
     */
	public function renderDefault($date = null)
	{

        try {
            $this->dates = $this->model->getDetectionLogList();
        } catch(HSCException $e) {}

        try {

            if($date)
                $date = new DateTime53($date);
            if(!$date && !empty($this->dates))
                $date = end($this->dates)->date;
            if(!$date)
                $date = new DateTime53();

            $this->template->date = $date;
            $this['frmDate']['date']->setDefaultValue( $date->format( $this->formats->date ) );


            $list = $this->model->getDetectionLog( $date );
            $this->template->list = empty($list) ? null : array_reverse( $list );
        } catch(HSCException $e) {
            $this->flashMessage( $e->getMessage(), 'error' );
        }

        if($this->isAjax)
            $this->invalidateControl();
	}

    /**
     * Create date form
     * @return AppForm
     */
    public function createComponentFrmDate() {
        $frm = new AppForm();
        $frm->addDatepicker('date','Date')
            ->setDefaultValue($this->date);
        $frm->addSubmit('send','Submit');
        $frm->onSuccess[] = array($this,'frmDateSuccess');
        return $frm;
    }

    /**
     * Callback on success date form
     * @param Form $frm
     */
    public function frmDateSuccess(Form $frm) {
        $this->date = $frm->values->date->format("Y-m-d");
        if($this->isAjax())
            $this->invalidateControl();
        else
            $this->redirect('this');
    }


}
