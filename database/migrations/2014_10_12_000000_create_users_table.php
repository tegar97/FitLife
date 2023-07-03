<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->integer('age')->nullable();
            $table->enum('gender', ['laki-laki', 'perempuan'])->nullable();
            $table->integer('height')->nullable();
            $table->integer('weight')->nullable();
            $table->double('bmi')->nullable();
            $table->enum('goal', ['gain', 'loss', 'maintain'])->nullable();
            $table->integer('target_weight')->nullable();
            $table->integer('point')->nullable();
            $table->integer('coin')->default(0);
            $table->integer('bamboo')->default(50);
            $table->boolean('vip')->default(false);
            $table->boolean('is_surveyed')->default(false);
            $table->date('vip_expires_at')->nullable();



            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
