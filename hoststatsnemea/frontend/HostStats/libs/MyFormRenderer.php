<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Forms\Rendering
 */



/**
 * Converts a Form into the HTML output.
 *
 * @author     David Grudl
 * @package Nette\Forms\Rendering
 */
class MyFormRenderer extends DefaultFormRenderer
{
	/**
	 *  /--- form.container
	 *
	 *    /--- if (form.errors) error.container
	 *      .... error.item [.class]
	 *    \---
	 *
	 *    /--- hidden.container
	 *      .... HIDDEN CONTROLS
	 *    \---
	 *
	 *    /--- group.container
	 *      .... group.label
	 *      .... group.description
	 *
	 *      /--- controls.container
	 *
	 *        /--- pair.container [.required .optional .odd]
	 *
	 *          /--- label.container
	 *            .... LABEL
	 *            .... label.suffix
	 *            .... label.requiredsuffix
	 *          \---
	 *
	 *          /--- control.container [.odd]
	 *            .... CONTROL [.required .text .password .file .submit .button]
	 *            .... control.requiredsuffix
	 *            .... control.description
	 *            .... if (control.errors) error.container
	 *          \---
	 *        \---
	 *      \---
	 *    \---
	 *  \--
	 *
	 * @var array of HTML tags */
	public $wrappers = array(
		'form' => array(
			'container' => 'div class=form-horizontal',
			'errors' => TRUE,
		),

		'error' => array(
			'container' => 'div class="alert alert-error nohide"',
            'list' => 'ul',
			'item' => 'li',
		),

		'group' => array(
			'container' => 'fieldset',
			'label' => 'legend',
			'description' => 'p',
		),

		'controls' => array(
			'container' => null,
		),

		'pair' => array(
			'container' => 'div class=control-group',
			'.required' => 'required',
			'.optional' => NULL,
			'.odd' => NULL,
		),

		'control' => array(
			'container' => 'div class="controls"',
			'.odd' => NULL,

			'errors' => FALSE,
			'description' => 'small',
			'requiredsuffix' => '',

			'.required' => 'required',
			'.text' =>  null,//'text',
			'.password' => null,//'text',
			'.file' => 'text',
			'.submit' => 'btn',
			'.image' => 'imagebutton',
			'.button' => 'btn',
		),

		'label' => array(
			'container' => 'div class=control-label',
			'suffix' => NULL,
			'requiredsuffix' => '',
		),

		'hidden' => array(
			'container' => 'div',
		),
	);
    
    
    public function renderErrors(IFormControl $control = NULL)
    {
        $errors = $control === NULL ? $this->form->getErrors() : $control->getErrors();
        if (count($errors)) {
            $div = $this->getWrapper('error container');
            $ul = $this->getWrapper('error list');
            $li = $this->getWrapper('error item');

            foreach ($errors as $error) {
                $item = clone $li;
                if ($error instanceof Html) {
                    $item->add($error);
                } else {
                    $item->setText($error);
                }
                $ul->add($item);
            }
            
            $div->add('<button type="button" class="close" data-dismiss="alert">×</button>');
            //$div->add('<h4>Opravte prosím formulář!</h4>');
            $div->add($ul);
            
            return "\n" . $div->render(0);
        }
    }
    
    public function renderControl(IFormControl $control)
    {
        $body = $this->getWrapper('control container');
        if ($this->counter % 2) {
            $body->class($this->getValue('control .odd'), TRUE);
        }

        $description = $control->getOption('description');
        if ($description instanceof Html) {
            $description = ' ' . $control->getOption('description');
        } elseif (is_string($description)) {
            $description = ' ' . $this->getWrapper('control description')->setText($control->translate($description));
        } else {
            $description = '';
        }

        if ($control->isRequired()) {
            $description = $this->getValue('control requiredsuffix') . $description;
        }

        if ($this->getValue('control errors')) {
            $description .= $this->renderErrors($control);
        }

        if ($control instanceof Checkbox) {
            $label = clone $control->getLabel();
            $label->class('chekbox');
            $label->setHtml((string) $control->getControl() . $control->getLabel()->getText());
            
            return $body->setHtml((string) $label . $description);
        } elseif ($control instanceof RadioList) {
            //$label = clone $control->getLabel();
            //$label->class('radio');
            
            return $body->setHtml((string) $control->getControl() . $description);
        } elseif($control instanceof Button) {
             $control->getControl()->class('btn');
            return $body->setHtml((string) $control->getControl() .(string) $control->getLabel() . $description);
        } else {
            return $body->setHtml((string) $control->getControl() . $description);
        }
    }


}
